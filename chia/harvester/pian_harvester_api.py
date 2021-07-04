from pathlib import Path
from typing import Callable, List, Tuple, Any, Dict, Optional

from blspy import AugSchemeMPL, G2Element

from chia.consensus.pot_iterations import calculate_iterations_quality, calculate_sp_interval_iters
from chia.harvester.harvester import Harvester
from chia.plotting.plot_tools import PlotInfo, parse_plot_info
from chia.protocols import harvester_protocol
from chia.protocols.farmer_protocol import FarmingInfo
from chia.protocols.protocol_message_types import ProtocolMessageTypes
from chia.server.outbound_message import make_msg
from chia.server.ws_connection import WSChiaConnection
from chia.types.blockchain_format.proof_of_space import ProofOfSpace
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.util.api_decorators import api_request, peer_required
from chia.util.ints import uint8, uint32, uint64
from chia.wallet.derive_keys import master_sk_to_local_sk
from chia.util.config import save_config
import json
import aiohttp

from chia.protocols.pool_protocol import (
    get_current_authentication_token,
    PoolErrorCode,
    PoolErrorCode,
    PostPartialRequest,
    PostPartialPayload,
)

class Mixin:

    def save_pian_setting(self):
        save_config(self.harvester.root_path,"pianpool.yaml", self.harvester.pian_config)


    def pian_blocking_lookup(self, filename: Path, plot_info: PlotInfo, new_challenge) -> List[Tuple[bytes32, ProofOfSpace]]:
        # Uses the DiskProver object to lookup qualities. This is a blocking call,
        # so it should be run in a thread pool.
        try:
            plot_id = plot_info.prover.get_id()
            sp_challenge_hash = ProofOfSpace.calculate_pos_challenge(
                plot_id,
                new_challenge.challenge_hash,
                new_challenge.sp_hash,
            )
            try:
                quality_strings = plot_info.prover.get_qualities_for_challenge(sp_challenge_hash)
            except Exception as e:
                self.harvester.log.error(f"Error using prover object {e}")
                self.harvester.log.error(
                    f"File: {filename} Plot ID: {plot_id.hex()}, "
                    f"challenge: {sp_challenge_hash}, plot_info: {plot_info}"
                )
                return []

            responses: List[Tuple[bytes32, ProofOfSpace]] = []
            if quality_strings is not None:
                difficulty = self.harvester.pian_config["pool"]["difficulty"]
                sub_slot_iters = 37600000000

                if plot_info.pool_contract_puzzle_hash is not None:
                    # we only handle legacy protocol
                    return []

                
                # Found proofs of space (on average 1 is expected per plot)
                for index, quality_str in enumerate(quality_strings):
                    required_iters: uint64 = calculate_iterations_quality(
                        self.harvester.constants.DIFFICULTY_CONSTANT_FACTOR,
                        quality_str,
                        plot_info.prover.get_size(),
                        difficulty, 
                        new_challenge.sp_hash,
                    )
                    sp_interval_iters = calculate_sp_interval_iters(
                        self.harvester.constants, sub_slot_iters
                    )
                    if required_iters < sp_interval_iters:
                        # Found a very good proof of space! will fetch the whole proof from disk,
                        # then send to farmer
                        try:
                            proof_xs = plot_info.prover.get_full_proof(sp_challenge_hash, index)
                            #self.harvester.log.error(f"Error using prover object {proof_xs}")
                        except Exception as e:
                            self.harvester.log.error(f"Exception fetching full proof for {filename}. {e}")
                            self.harvester.log.error(
                                f"File: {filename} Plot ID: {plot_id.hex()}, challenge: {sp_challenge_hash}, "
                                f"plot_info: {plot_info}"
                            )
                            continue

                        # Look up local_sk from plot to save locked memory
                        (
                            pool_public_key_or_puzzle_hash,
                            farmer_public_key,
                            local_master_sk,
                        ) = parse_plot_info(plot_info.prover.get_memo())
                        local_sk = master_sk_to_local_sk(local_master_sk)
                        plot_public_key = ProofOfSpace.generate_plot_public_key(
                            local_sk.get_g1(), farmer_public_key
                        )
                        responses.append(
                            (
                                quality_str,
                                ProofOfSpace(
                                    sp_challenge_hash,
                                    plot_info.pool_public_key,
                                    plot_info.pool_contract_puzzle_hash,
                                    plot_public_key,
                                    uint8(plot_info.prover.get_size()),
                                    proof_xs,
                                ),
                            )
                        )
            return responses
        except Exception as e:
            self.harvester.log.error(f"Unknown error: {e}")
            return []

    async def pian_lookup_challenge(self,
        filename: Path, plot_info: PlotInfo,new_challenge, loop, peer
    ) -> Tuple[Path, List[harvester_protocol.NewProofOfSpace]]:
        # Executes a DiskProverLookup in a thread pool, and returns responses
        plot_id = plot_info.prover.get_id().hex()
        all_responses: List[harvester_protocol.NewProofOfSpace] = []
        if self.harvester._is_shutdown:
            return plot_id, []
        proofs_of_space_and_q: List[Tuple[bytes32, ProofOfSpace]] = await loop.run_in_executor(
            self.harvester.executor, self.pian_blocking_lookup, filename, plot_info, new_challenge
        )
        for quality_str, proof_of_space in proofs_of_space_and_q:
            all_responses.append(
                harvester_protocol.NewProofOfSpace(
                    new_challenge.challenge_hash,
                    new_challenge.sp_hash,
                    quality_str.hex() + str(filename.resolve()),
                    proof_of_space,
                    new_challenge.signage_point_index,
                )
            )
        for response in all_responses:
            await self.pian_new_proof_of_space(response,peer)

        return plot_id, all_responses
        
    async def pian_new_proof_of_space(
        self, new_proof_of_space: harvester_protocol.NewProofOfSpace, peer
    ):

        self.harvester.log.warning(f"{new_proof_of_space}")

        p2_singleton_puzzle_hash = new_proof_of_space.proof.pool_contract_puzzle_hash

        #only send legacy plots to pianpool
        if p2_singleton_puzzle_hash is None:

            #pool_state_dict: Dict = self.harvester.pian_pool_state
            pool_url = self.harvester.pian_config["pool"]["url"]
            if pool_url == "":
                self.harvester.log.warning(f"No pool url")
                return

            if self.harvester.pian_config["pool"]["difficulty"] is None:
                self.harvester.log.warning(
                    f"No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, "
                    f"check communication with the pool, skipping this partial to {pool_url}."
                )
                return

            authentication_token_timeout = self.harvester.pian_config["pool"]["authentication_token_timeout"]
            if authentication_token_timeout is None:
                self.harvester.log.warning(
                    f"No pool specific authentication_token_timeout has been set for {p2_singleton_puzzle_hash}"
                    f", check communication with the pool."
                )
                return

            # Submit partial to pool
            is_eos = new_proof_of_space.signage_point_index == 0

            payload = PostPartialPayload(
                peer.peer_node_id,
                get_current_authentication_token(authentication_token_timeout),
                new_proof_of_space.proof,
                new_proof_of_space.sp_hash,
                is_eos,
                peer.peer_node_id,
            )

            agg_sig: G2Element = G2Element.generator()
            post_partial_request:PostPartialRequest = PostPartialRequest(payload,agg_sig)
            post_partial_body = json.dumps(post_partial_request.to_json_dict())

            self.harvester.log.info(
                f"Submitting partial for {post_partial_request.payload.launcher_id.hex()} to {pool_url} {post_partial_body}"
            )
            #pool_state_dict["points_found_since_start"] += pool_state_dict["current_difficulty"]
            #pool_state_dict["points_found_24h"].append((time.time(), pool_state_dict["current_difficulty"]))
            user = self.harvester.pian_config["pool"]["user"]
            rig = self.harvester.pian_config["pool"]["rig"]
            try:
                async with aiohttp.ClientSession() as session:
                    headers = {'content-type': 'application/json'}
                    async with session.post(f"{pool_url}/legacy_pool/partial?user={user}&rig={rig}", data=post_partial_body,headers=headers) as resp:
                        if resp.ok:
                            pool_response: Dict = json.loads(await resp.text())
                            self.harvester.log.info(f"Pool response: {pool_response}")
                            if "error_code" in pool_response:
                                self.harvester.log.error(
                                    f"Error in pooling: "
                                    f"{pool_response['error_code'], pool_response['error_message']}"
                                )
                                #pool_state_dict["pool_errors_24h"].append(pool_response)
                                if pool_response["error_code"] == PoolErrorCode.PROOF_NOT_GOOD_ENOUGH.value:
                                    self.harvester.log.error(
                                        "Partial not good enough, forcing pool farmer update to "
                                        "get our current difficulty."
                                    )
                                    self.harvester.pian_config["pool"]["difficulty"] = pool_response["new_difficulty"]
                                    self.save_pian_setting()
                                    
                            else:

                                if self.harvester.pian_config["pool"]["difficulty"] != pool_response["new_difficulty"]:
                                    self.harvester.pian_config["pool"]["difficulty"] = pool_response["new_difficulty"]
                                    self.save_pian_setting()
                                #pool_state_dict["points_acknowledged_since_start"] += new_difficulty
                                #pool_state_dict["points_acknowledged_24h"].append((time.time(), new_difficulty))
                                #pool_state_dict["current_difficulty"] = new_difficulty
                        else:
                            self.harvester.log.error(f"Error sending partial to {pool_url}, {resp.status}")
            except Exception as e:
                self.harvester.log.error(f"Error connecting to pool: {e}")
                return

            return

    async def submit_pian_share(self,plotids,new_challenge):
        if not plotids:
            return
        user = self.harvester.pian_config["pool"]["user"]
        rig = self.harvester.pian_config["pool"]["rig"]
        pool_url = self.harvester.pian_config["pool"]["url"]


        obj = {
                "user" : user,
                "rig"  : rig,
                "challenge_hash" : new_challenge.challenge_hash.hex(),
                "sp_hash"        : new_challenge.sp_hash.hex(),
                "eligible_plots" : plotids
            }

        json_data = json.dumps(obj).encode("utf-8")

        try:
            async with aiohttp.ClientSession() as session:
                headers = {'content-type': 'application/json'}
                async with session.post(f"{pool_url}/legacy_pool/submit_share", data=json_data, headers=headers) as resp:
                    if resp.ok:
                        pool_response: Dict = json.loads(await resp.text())
                        self.harvester.log.info(f"Pool response: {pool_response}")

                    else:
                        self.harvester.log.error(f"Error sending share to {pool_url}, {resp.status}")
        except Exception as e:
            self.harvester.log.error(f"Error connecting to pool 1: {e}")
            return

        return        
