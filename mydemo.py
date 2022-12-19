import asyncio
import time
import json

from indy import anoncreds, did, ledger, pool, wallet, IndyError, blob_storage
from indy.error import ErrorCode, errorcode_to_exception


async def run():
    print("Getting started -> started")
    print("\n=====================================================================")
    print("=== Getting pool connection")

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(2)

    pool_ = {
        'name': 'pool1',
        'config': json.dumps({"genesis_txn": '/home/indy/sandbox/pool_transactions_genesis'})
    }
    print("Open Pool Ledger: {}".format(pool_['name']))

    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("\n=====================================================================")
    print("=== Getting Endorser credentials for Faber, Acme and Government")

    steward = {
        'name': "Sovrin Steward",
        'wallet_config': json.dumps({'id': 'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }

    await create_wallet(steward)

    print("Sovrin Steward -> Create and store in Wallet DID from seed")
    steward['did_info'] = json.dumps({'seed': steward['seed']})
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])

    print("\n=====================================================================")
    print("== Getting Endorser credentials - Government getting Verinym")

    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'ENDORSER'
    }

    await getting_verinym(steward, government)

    print("\n=====================================================================")
    print("== Getting Endorser credentials - Faber getting Verinym")

    faber = {
        'name': 'Faber',
        'wallet_config': json.dumps({'id': 'faber_wallet'}),
        'wallet_credentials': json.dumps({'key': 'faber_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'ENDORSER'
    }

    await getting_verinym(steward, faber)

    print("\n=====================================================================")
    print("== Getting Endorser credentials - Acme getting Verinym")

    acme = {
        'name': 'Acme',
        'wallet_config': json.dumps({'id': 'acme_wallet'}),
        'wallet_credentials': json.dumps({'key': 'acme_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'ENDORSER'
    }

    await getting_verinym(steward, acme)

    print("\n=====================================================================")
    print("== Alice setup ==")

    alice = {
        'name': 'Alice',
        'wallet_config': json.dumps({'id': 'alice_wallet'}),
        'wallet_credentials': json.dumps({'key': 'alice_wallet_key'}),
        'pool': pool_['handle'],
        'last_revoc_update': None
    }
    await create_wallet(alice)
    (alice['did'], alice['key']) = await did.create_and_store_my_did(alice['wallet'], "{}")

    # ---------------------------------- SCHEMA AND CRED DEF SET-UP ---------------------------------- #

    print("\n=====================================================================")
    print("=== Credential Schemas Setup ==")

    print("Government -> Create Transcript Schema")
    transcript = {
        'name': 'Transcript',
        'version': '1.2',
        'attributes': ['first_name', 'last_name', 'degree', 'status', 'year', 'average', 'ssn']
    }
    (government['transcript_schema_id'], government['transcript_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], transcript['name'], transcript['version'],
                                             json.dumps(transcript['attributes']))
    transcript_schema_id = government['transcript_schema_id']

    print("Government -> Send Transcript Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['transcript_schema'])

    time.sleep(1)  # sleep 1 second before getting schema

    print("\n=====================================================================")
    print("=== Faber Credential Definition Setup ==")

    print("Faber -> Get Transcript Schema from Ledger")
    (faber['transcript_schema_id'], faber['transcript_schema']) = \
        await get_schema(faber['pool'], faber['did'], transcript_schema_id)

    print("Faber -> Create and store in Wallet Faber Transcript Credential Definition")
    transcript_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": True}
    }
    (faber['transcript_cred_def_id'], faber['transcript_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(faber['wallet'], faber['did'],
                                                               faber['transcript_schema'], transcript_cred_def['tag'],
                                                               transcript_cred_def['type'],
                                                               json.dumps(transcript_cred_def['config']))

    print("Faber -> Send  Faber Transcript Credential Definition to Ledger")
    await send_cred_def(faber['pool'], faber['wallet'], faber['did'], faber['transcript_cred_def'])

    print("\n=====================================================================")
    print("=== Faber Revocation Registry Setup ==")

    # Convert existing data to variables from test
    issuer_wallet_handle = faber['wallet']
    issuer_did = faber["did"]
    cred_def_id = faber['transcript_cred_def_id']
    pool_handle = pool_['handle']

    #  Issuer Creates Revocation Registry
    print("Faber -> Create revocation registry")
    tails_writer_config = json.dumps({'base_dir': '/home/indy/sandbox/tails', 'uri_pattern': ''})
    tails_writer = await blob_storage.open_writer('default', tails_writer_config)

    # NOTE: rev_reg_id is sometimes referred to as rev_reg_def_id, but they're the same thing
    (rev_reg_id, rev_reg_def_json, rev_reg_entry_json) = \
        await anoncreds.issuer_create_and_store_revoc_reg(issuer_wallet_handle, issuer_did, None, 'tag1', cred_def_id,
                                                          '{"max_cred_num": 5, "issuance_type":"ISSUANCE_ON_DEMAND"}',
                                                          tails_writer)

    # Issuer posts Revocation Registry Definition to Ledger
    print("Faber -> Send Revocation Registry Definition to Ledger")
    revoc_reg_request = await ledger.build_revoc_reg_def_request(issuer_did, rev_reg_def_json)
    await ledger.sign_and_submit_request(pool_handle, issuer_wallet_handle, issuer_did, revoc_reg_request)

    # Issuer posts Revocation Registry Entry to Ledger
    print("Faber -> send Revocation Registry Entry to Ledger")
    revoc_reg_entry_request = \
        await ledger.build_revoc_reg_entry_request(issuer_did, rev_reg_id, "CL_ACCUM", rev_reg_entry_json)
    await ledger.sign_and_submit_request(pool_handle, issuer_wallet_handle, issuer_did, revoc_reg_entry_request)

    time.sleep(1)  # sleep 1 second before using the freshly created revocable creds
    # ---------------------------------- EXCHANGING CREDENTIALS ---------------------------------- #

    print("\n=====================================================================")
    print("== Getting Transcript with Faber - Getting Transcript Credential ==")

    # Issuer creates transcript credential
    print("Faber -> Create Transcript Credential Offer for Alice")
    faber['transcript_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(faber['wallet'], faber['transcript_cred_def_id'])

    # Issuer sends transcript credential to prover
    print("Faber -> Send Transcript Credential Offer to Alice")
    alice['transcript_cred_offer'] = faber['transcript_cred_offer']
    transcript_cred_offer_object = json.loads(alice['transcript_cred_offer'])

    alice['transcript_schema_id'] = transcript_cred_offer_object['schema_id']
    alice['transcript_cred_def_id'] = transcript_cred_offer_object['cred_def_id']

    # Prover creates and stores master secret in their wallet
    print("Alice -> Create and store Alice Master Secret in Wallet")
    alice['master_secret_id'] = await anoncreds.prover_create_master_secret(alice['wallet'], None)

    # Prover gets credential def from Ledger
    print("Alice -> Get Faber Transcript Credential Definition from Ledger")
    (alice['faber_transcript_cred_def_id'], alice['faber_transcript_cred_def']) = \
        await get_cred_def(alice['pool'], alice['did'], alice['transcript_cred_def_id'])

    # Prover creates credential request for Issuer
    print("Alice -> Create Transcript Credential Request for Faber")
    (alice['transcript_cred_request'], alice['transcript_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(alice['wallet'], alice['did'],
                                                     alice['transcript_cred_offer'], alice['faber_transcript_cred_def'],
                                                     alice['master_secret_id'])

    # Prover sends credential request to Issuer
    print("Alice -> Send Transcript Credential Request to Faber")
    faber['transcript_cred_request'] = alice['transcript_cred_request']

    alice['transcript_cred_values'] = json.dumps({
        "first_name": {"raw": "Alice", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
        "degree": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
        "status": {"raw": "graduated", "encoded": "2213454313412354"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "year": {"raw": "2015", "encoded": "2015"},
        "average": {"raw": "5", "encoded": "5"}
    })
    faber['alice_transcript_cred_values'] = alice['transcript_cred_values']

    # Issuer creates credential
    print("Faber -> Create Transcript Credential for Alice")

    tails_reader = \
        await blob_storage.open_reader('default', tails_writer_config)  # Issuer opens tails file reader

    (faber['transcript_cred'], local_cred_id_for_revoc, rev_reg_delta_json) = \
        await anoncreds.issuer_create_credential(faber['wallet'], faber['transcript_cred_offer'],
                                                 faber['transcript_cred_request'],
                                                 faber['alice_transcript_cred_values'],
                                                 rev_reg_id,
                                                 tails_reader)
    # Note that in the above, revocation registry data is passed to issue the credential

    # Issuer Posts Revocation Registry Delta to Ledger
    print("Faber -> Send revocation registry delta to Ledger")
    await send_revoc_reg_delta(pool_handle, issuer_wallet_handle, issuer_did, rev_reg_id, rev_reg_delta_json)

    # Issuer sends credential to Prover
    print("Faber -> Send Transcript Credential to Alice")
    alice['transcript_cred'] = faber['transcript_cred']

    # Prover Gets RevocationRegistryDefinition from Ledger
    print("Alice -> Get revocation registry definition from Ledger")
    prover_did = alice['did']
    credential = json.loads(alice['transcript_cred'])

    (rev_reg_id, revoc_reg_def_json) = await get_revoc_reg_def(pool_handle, prover_did, credential['rev_reg_id'])

    # Prover stores credential and revocation data
    print("Alice -> Store the credential and revocation data")
    _, alice['transcript_cred_def'] = await get_cred_def(alice['pool'], alice['did'],
                                                         alice['transcript_cred_def_id'])

    await anoncreds.prover_store_credential(alice['wallet'], None,  # none = cred_id, can be any string I think
                                            alice['transcript_cred_request_metadata'],
                                            alice['transcript_cred'], alice['transcript_cred_def'], revoc_reg_def_json)

    # ---------------------------------- USING THE CREDENTIALS ---------------------------------- #

    print("\n=====================================================================")
    print("== Apply for the job with Acme - Transcript proving ==")

    print("Acme -> Create Job-Application Proof Request")
    nonce = await anoncreds.generate_nonce()
    acme['job_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'average',
                'p_type': '>=',
                'p_value': 4,
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            }
        }
    })

    print("Acme -> Send Job-Application Proof Request to Alice")
    alice['job_application_proof_request'] = acme['job_application_proof_request']

    print("Alice -> Get credentials for Job-Application Proof Request")

    search_handle = \
        await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                alice['job_application_proof_request'], None)

    # get_credential_for_referent = prover_fetch_credentials_for_proof_req
    cred_for_attr1 = await get_credential_for_referent(search_handle, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_handle, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_handle, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_handle, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_handle, 'attr5_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_handle, 'predicate1_referent')

    print("[i] Credential for attribute 3")
    print(cred_for_attr3)

    await anoncreds.prover_close_credentials_search_for_proof_req(search_handle)

    alice['creds_for_job_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_predicate1['referent']: cred_for_predicate1}
    # NOTE: the search returns the same cred (referent) each time, so this dict has one entry that's
    # being readded and is assumedly automatically skipped

    # Prover Gets RevocationRegistryDelta from Ledger
    # Prover Creates Revocation State
    # (both are done in prover_get_entities_from_ledger)

    request_time = get_current_time()
    alice['schemas'], alice['cred_defs'], alice['revoc_states'], timestamps = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did'],
                                              alice['creds_for_job_application_proof'], alice['name'],
                                              _from_time=alice['last_revoc_update'],
                                              _to_time=request_time,
                                              _tails_reader=tails_reader)
    alice['last_revoc_update'] = request_time

    # print("[i] Ledger entities")
    # print(alice['schemas'], '\n', alice['revoc_states'])

    print("Alice -> Create Job-Application Proof")
    alice['job_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Alice',
            'attr2_referent': 'Garcia',
            'attr6_referent': '123-45-6789'
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True, 'timestamp': timestamps[cred_for_attr3['referent']]},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True, 'timestamp': timestamps[cred_for_attr4['referent']]},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True, 'timestamp': timestamps[cred_for_attr5['referent']]},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent'], 'timestamp': timestamps[cred_for_attr4['referent']]}}
    })

    alice['job_application_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['job_application_proof_request'],
                                            alice['job_application_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("Alice -> Send Job-Application Proof to Acme")
    acme['job_application_proof'] = alice['job_application_proof']
    job_application_proof_object = json.loads(acme['job_application_proof'])

    print("[i] Identifiers received from Prover:")
    print(job_application_proof_object['identifiers'])

    for identifier in job_application_proof_object['identifiers']:
        assert identifier['timestamp'] is not None
        # Put correct timestamp in the requested credential if this fails.
        # otherwise get_revoc_reg() will fail while verifying

    acme['schemas_for_job_application'], acme['cred_defs_for_job_application'], \
        acme['revoc_reg_defs_for_job_application'], acme['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(acme['pool'], acme['did'],
                                                job_application_proof_object['identifiers'], acme['name'])

    print("Acme -> Verify Job-Application Proof from Alice")
    # assert 'Bachelor of Science, Marketing' == \
    #        job_application_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    # assert 'graduated' == \
    #        job_application_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    # assert '123-45-6789' == \
    #        job_application_proof_object['requested_proof']['revealed_attrs']['attr5_referent']['raw']
    #
    # assert 'Alice' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr1_referent']
    # assert 'Garcia' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr2_referent']
    # assert '123-45-6789' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr6_referent']

    # for testing
    # try:
    #     assert await anoncreds.verifier_verify_proof(acme['job_application_proof_request'],
    #                                                  acme['job_application_proof'],
    #                                                  acme['schemas_for_job_application'],
    #                                                  acme['cred_defs_for_job_application'],
    #                                                  acme['revoc_reg_defs_for_job_application'],
    #                                                  acme['revoc_regs_for_job_application'])
    # except IndyError as ex:
    #     print("[!] Exception occured")
    #     err = errorcode_to_exception(ex.error_code)
    #     print(err)

    assert await anoncreds.verifier_verify_proof(acme['job_application_proof_request'], acme['job_application_proof'],
                                                 acme['schemas_for_job_application'],
                                                 acme['cred_defs_for_job_application'],
                                                 acme['revoc_reg_defs_for_job_application'],
                                                 acme['revoc_regs_for_job_application'])

    print("\n=====================================================================")
    print("== Revoke credentials ==")

    print("Faber -> Revoke proof")
    rev_reg_delta_json = await anoncreds.issuer_revoke_credential(issuer_wallet_handle, tails_reader,
                                                                  rev_reg_id, local_cred_id_for_revoc)

    print("Faber -> Send revocation registry delta to Ledger")
    await send_revoc_reg_delta(pool_handle, issuer_wallet_handle, issuer_did, rev_reg_id, rev_reg_delta_json)

    print("\n=====================================================================")
    print("== Prover tries to use revoked credentials ==")
    # TODO verify again

    # ---------------------------------- CLEAN UP ---------------------------------- #

    print("\n=====================================================================")

    print("Sovrin Steward -> Close and Delete wallet")
    await wallet.close_wallet(steward['wallet'])
    await wallet.delete_wallet(steward['wallet_config'], steward['wallet_credentials'])

    print("Government -> Close and Delete wallet")
    await wallet.close_wallet(government['wallet'])
    await wallet.delete_wallet(government['wallet_config'], government['wallet_credentials'])

    print("Faber -> Close and Delete wallet")
    await wallet.close_wallet(faber['wallet'])
    await wallet.delete_wallet(faber['wallet_config'], faber['wallet_credentials'])

    print("Acme -> Close and Delete wallet")
    await wallet.close_wallet(acme['wallet'])
    await wallet.delete_wallet(acme['wallet_config'], acme['wallet_credentials'])

    print("Alice -> Close and Delete wallet")
    await wallet.close_wallet(alice['wallet'])
    await wallet.delete_wallet(alice['wallet_config'], alice['wallet_credentials'])

    print("Close and Delete pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("Getting started -> done")


# ---------------------------------- HELPER FUNCTIONS ---------------------------------- #

# --------- Request shorthands: basics
async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


# --------- Request shorthands: revocation
async def get_revoc_reg_def(pool_handle, _did, rev_reg_id):
    get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, rev_reg_id)
    get_revoc_reg_def_response = await ledger.submit_request(pool_handle, get_revoc_reg_def_request)
    return await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)
    # Returns (rev_reg_id, revoc_reg_def_json)


async def get_revoc_reg_delta(pool_handle, _did, _rev_reg_id, _from_time, _to_time):
    get_revoc_reg_delta_request = \
        await ledger.build_get_revoc_reg_delta_request(_did, _rev_reg_id, _from_time, _to_time)
    get_revoc_reg_delta_response = await ledger.submit_request(pool_handle, get_revoc_reg_delta_request)
    return await ledger.parse_get_revoc_reg_delta_response(get_revoc_reg_delta_response)
    # Return (rev_reg_id, revoc_reg_delta_json, timestamp)


async def get_revoc_reg(pool_handle, _did, _rev_reg_id, _timestamp):
    get_revoc_reg_request = \
        await ledger.build_get_revoc_reg_request(_did, _rev_reg_id, _timestamp)
    get_revoc_reg_response = await ledger.submit_request(pool_handle, get_revoc_reg_request)
    return await ledger.parse_get_revoc_reg_response(get_revoc_reg_response)
    # Returns (rev_reg_id, rev_reg_json, identifier)


async def send_revoc_reg_delta(pool_handle, wallet_handle, _did, _rev_reg_id, _rev_reg_delta_json):
    revoc_reg_entry_request = \
        await ledger.build_revoc_reg_entry_request(_did, _rev_reg_id, "CL_ACCUM", _rev_reg_delta_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, revoc_reg_entry_request)


# --------- Misc
async def create_wallet(identity):
    print("{} -> Create wallet".format(identity['name']))
    try:
        await wallet.create_wallet(identity['wallet_config'], identity['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    identity['wallet'] = await wallet.open_wallet(identity['wallet_config'], identity['wallet_credentials'])


async def getting_verinym(from_, to):
    await create_wallet(to)

    (to['did'], to['key']) = await did.create_and_store_my_did(to['wallet'], "{}")

    from_['info'] = {
        'did': to['did'],
        'verkey': to['key'],
        'role': to['role'] or None
    }

    await send_nym(from_['pool'], from_['wallet'], from_['did'], from_['info']['did'],
                   from_['info']['verkey'], from_['info']['role'])


async def get_credential_for_referent(_search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(_search_handle, referent, 10))
    return credentials[0]['cred_info']


def get_current_time() -> int:
    return int(time.time())


# ---------  Mass get data from ledger

async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor,
                                          _from_time=None, _to_time=None, _tails_reader=None):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    timestamps = {}  # Timestamps need to be saved to be put in the request proof

    for item in identifiers.values():
        print("{} -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("{} -> Get Credential Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if item['rev_reg_id'] is not None:
            print("{} -> Get Revoc delta from Ledger".format(actor))
            rev_reg_id = item['rev_reg_id']
            (rev_reg_id, revoc_reg_delta_json, timestamp) = \
                await get_revoc_reg_delta(pool_handle, _did, rev_reg_id, _from_time, _to_time)
            referent = item['referent']
            timestamps[referent] = timestamp
            print("[i] Timestamp for", referent, "=", timestamp)
            print("{} -> Get revocation definition".format(actor))
            (rev_reg_id, revoc_reg_def_json) = await get_revoc_reg_def(pool_handle, _did, rev_reg_id)
            print("{} -> Create revocation state".format(actor))
            rev_state_json = await anoncreds.create_revocation_state(_tails_reader, revoc_reg_def_json,
                                                                     revoc_reg_delta_json, timestamp,
                                                                     item['cred_rev_id'])
            rev_states[rev_reg_id] = {timestamp: json.loads(rev_state_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states), timestamps


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        print("{} -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("{} -> Get Credential Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if item['rev_reg_id'] is not None:
            print("{} -> Get revocation definition".format(actor))
            rev_reg_id = item['rev_reg_id']
            (rev_reg_id, revoc_reg_def_json) = await get_revoc_reg_def(pool_handle, _did, rev_reg_id)
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)
            print("{} -> Get revocation registry".format(actor))
            timestamp = item['timestamp']
            (rev_reg_id, rev_reg_json, identifier) = await get_revoc_reg(pool_handle, _did, rev_reg_id, timestamp)
            rev_regs[rev_reg_id] = {timestamp: json.loads(rev_reg_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


await run()
