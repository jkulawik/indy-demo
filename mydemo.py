import asyncio
import time
import json

from indy import anoncreds, did, ledger, pool, wallet, IndyError, blob_storage
from indy.error import ErrorCode, errorcode_to_exception


async def run():
    print("\n=====================================================================")
    print("=== Connect to pool and set up the Steward")
    await pool.set_protocol_version(2)  # Set protocol version 2 to work with Indy Node 1.4

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

    print("Sovrin Steward -> Create wallet")
    steward = {
        'name': "Sovrin Steward",
        'wallet_config': json.dumps({'id': 'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }
    await create_wallet(steward)

    print("Sovrin Steward -> Create and store DID from seed in Wallet")
    steward['did_info'] = json.dumps({'seed': steward['seed']})
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])

    print("\n=====================================================================")
    print("=== Getting Endorser credentials for Carrier A, Carrier B and Government")

    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'ENDORSER'
    }
    await create_wallet_and_register_verinym(steward, government)

    carrier_a = {
        'name': 'Carrier A',
        'wallet_config': json.dumps({'id': 'carrier_a_wallet'}),
        'wallet_credentials': json.dumps({'key': 'carrier_a_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'ENDORSER'
    }
    await create_wallet_and_register_verinym(steward, carrier_a)

    carrier_b = {
        'name': 'Carrier B',
        'wallet_config': json.dumps({'id': 'carrier_b_wallet'}),
        'wallet_credentials': json.dumps({'key': 'carrier_b_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'ENDORSER'
    }
    await create_wallet_and_register_verinym(steward, carrier_b)

    university = {
        'name': 'Warsaw University of Technology',
        'wallet_config': json.dumps({'id': 'university_wallet'}),
        'wallet_credentials': json.dumps({'key': 'university_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'ENDORSER'
    }
    await create_wallet_and_register_verinym(steward, university)

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
    print("Alice -> Create DID and store it in her wallet")
    (alice['did'], alice['key']) = await did.create_and_store_my_did(alice['wallet'], "{}")

    # ---------------------------------- SCHEMA AND CRED DEF SET-UP ---------------------------------- #

    print("\n=====================================================================")
    print("=== Credential Schemas Setup ==")

    print("Government -> Create City Card Schema")
    city_card = {
        'name': 'City Card',
        'version': '1.0',
        'attributes': ['first_name', 'last_name', 'city', 'half_price', 'max_zone']
    }
    # 'attributes': ['first_name', 'last_name', 'city', 'half_price', 'max_zone']
    # 'attributes': ['first_name', 'last_name', 'degree', 'status', 'year', 'average', 'ssn']
    (government['cc_schema_id'], government['cc_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], city_card['name'], city_card['version'],
                                             json.dumps(city_card['attributes']))
    cc_schema_id = government['cc_schema_id']

    print("Government -> Send City Card Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['cc_schema'])

    print("Government -> Create Student Card Schema")
    student_card = {
        'name': 'Student Card',
        'version': '1.0',
        'attributes': ['first_name', 'last_name', 'album_number']
    }

    (government['sc_schema_id'], government['sc_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], student_card['name'], student_card['version'],
                                             json.dumps(student_card['attributes']))
    sc_schema_id = government['sc_schema_id']

    print("Government -> Send Student Card Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['sc_schema'])

    time.sleep(1)  # sleep 1 second before getting schema

    print("\n=====================================================================")
    print("=== Carrier Credential Definition Setup ==")

    carriers = [carrier_a, carrier_b]

    for carrier in carriers:
        print("{} -> Get City Card Schema from Ledger".format(carrier['name']))
        (carrier['cc_schema_id'], carrier['cc_schema']) = \
            await get_schema(carrier['pool'],
                             carrier['did'],
                             cc_schema_id)  # Carrier must know schema ID beforehand

        print("{} -> Create and store City Card Credential Definition in Wallet".format(carrier['name']))
        cc_cred_def = {
            'tag': 'TAG1',
            'type': 'CL',
            'config': {"support_revocation": True}
        }
        (carrier['cc_cred_def_id'], carrier['cc_cred_def']) = \
            await anoncreds.issuer_create_and_store_credential_def(carrier['wallet'], carrier['did'],
                                                                   carrier['cc_schema'], cc_cred_def['tag'],
                                                                   cc_cred_def['type'],
                                                                   json.dumps(cc_cred_def['config']))

        print("{} -> Send  City Card Credential Definition to Ledger".format(carrier['name']))
        await send_cred_def(carrier['pool'], carrier['wallet'], carrier['did'], carrier['cc_cred_def'])

    print("{} -> Get Student Card Schema from Ledger".format(university['name']))
    (university['sc_schema_id'], university['sc_schema']) = \
        await get_schema(university['pool'],
                         university['did'],
                         sc_schema_id)  # Carrier must know schema ID beforehand

    print("{} -> Create and store Student Card Credential Definition in Wallet".format(university['name']))
    sc_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": True}
    }
    (university['sc_cred_def_id'], university['sc_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(university['wallet'], university['did'],
                                                               university['sc_schema'], sc_cred_def['tag'],
                                                               sc_cred_def['type'],
                                                               json.dumps(sc_cred_def['config']))

    print("{} -> Send  City Card Credential Definition to Ledger".format(university['name']))
    await send_cred_def(university['pool'], university['wallet'], university['did'], university['sc_cred_def'])

    print("\n=====================================================================")
    print("=== Carrier A Revocation Registry Setup ==")

    #  Issuer Creates Revocation Registry
    print("Carrier A -> Create revocation registry")
    tails_writer_config = json.dumps({'base_dir': '/home/indy/sandbox/tails', 'uri_pattern': ''})
    tails_writer = await blob_storage.open_writer('default', tails_writer_config)

    # NOTE: rev_reg_id is sometimes referred to as rev_reg_def_id, but they're the same thing
    (carrier_a['rev_reg_id'], rev_reg_def_json, rev_reg_entry_json) = \
        await anoncreds.issuer_create_and_store_revoc_reg(carrier_a['wallet'], carrier_a['did'], None, 'tag1',
                                                          carrier_a['cc_cred_def_id'],
                                                          '{"max_cred_num": 5, "issuance_type":"ISSUANCE_ON_DEMAND"}',
                                                          tails_writer)

    # Issuer posts Revocation Registry Definition to Ledger
    print("Carrier A -> Send Revocation Registry Definition to Ledger")
    revoc_reg_request = await ledger.build_revoc_reg_def_request(carrier_a['did'], rev_reg_def_json)
    await ledger.sign_and_submit_request(carrier_a['pool'], carrier_a['wallet'], carrier_a['did'], revoc_reg_request)

    # Issuer posts Revocation Registry Entry to Ledger
    print("Carrier A -> send Revocation Registry Entry to Ledger")
    revoc_reg_entry_request = await ledger.build_revoc_reg_entry_request(carrier_a['did'], carrier_a['rev_reg_id'],
                                                                         "CL_ACCUM", rev_reg_entry_json)
    await ledger.sign_and_submit_request(carrier_a['pool'], carrier_a['wallet'],
                                         carrier_a['did'], revoc_reg_entry_request)

    time.sleep(1)  # sleep 1 second before using the freshly created revocable creds

    # ---------------------------------- EXCHANGING CREDENTIALS ---------------------------------- #

    print("\n=====================================================================")
    print("== Alice gets City Card from Carrier A - Getting City Card Credential ==")

    # Issuer creates a City Card credential
    print("Carrier A -> Create City Card Credential Offer for Alice")
    carrier_a['cc_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(carrier_a['wallet'], carrier_a['cc_cred_def_id'])

    # Issuer sends City Card credential to prover
    print("Carrier A -> Send City Card Credential Offer to Alice")
    alice['cc_cred_offer'] = carrier_a['cc_cred_offer']
    cc_cred_offer_object = json.loads(alice['cc_cred_offer'])

    alice['cc_schema_id'] = cc_cred_offer_object['schema_id']
    alice['cc_cred_def_id'] = cc_cred_offer_object['cred_def_id']

    # Prover creates and stores master secret in their wallet
    print("Alice -> Create and store Alice Master Secret in Wallet")
    alice['master_secret_id'] = await anoncreds.prover_create_master_secret(alice['wallet'], None)

    # Prover gets credential def from Ledger
    print("Alice -> Get City Card Credential Definition from Ledger")
    (alice['cc_cred_def_id'], alice['cc_cred_def']) = \
        await get_cred_def(alice['pool'], alice['did'], alice['cc_cred_def_id'])

    # Prover creates credential request for Issuer
    print("Alice -> Create City Card Credential Request for Carrier A")
    (alice['cc_cred_request'], alice['cc_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(alice['wallet'], alice['did'],
                                                     alice['cc_cred_offer'], alice['cc_cred_def'],
                                                     alice['master_secret_id'])

    # Prover sends credential request to Issuer
    print("Alice -> Send City Card Credential Request to Carrier A")
    carrier_a['cc_cred_request'] = alice['cc_cred_request']

    print("Alice -> Fill her data and send to Carrier A")
    # alice['cc_cred_values'] = json.dumps({
    #     "first_name": {"raw": "Alice", "encoded": "1139481716457488690172217916278103335"},
    #     "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
    #     "degree": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
    #     "status": {"raw": "graduated", "encoded": "2213454313412354"},
    #     "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
    #     "year": {"raw": "2015", "encoded": "2015"},
    #     "average": {"raw": "5", "encoded": "5"}
    # })
    alice['cc_cred_values'] = json.dumps({
        "first_name": {"raw": "Alice", "encoded": encode('Alice')},
        "last_name": {"raw": "Garcia", "encoded": encode('Garcia')},
        "city": {"raw": "Warsaw", "encoded": encode('Warsaw')},
        "half_price": {"raw": "false", "encoded": encode('false')},
        "max_zone": {"raw": "2", "encoded": "2"},
    })
    carrier_a['alice_cc_cred_values'] = alice['cc_cred_values']

    # Issuer creates credential
    print("Carrier A -> Create City Card Credential for Alice")

    tails_reader = \
        await blob_storage.open_reader('default', tails_writer_config)  # Issuer opens tails file reader

    (carrier_a['cc_cred'], carrier_a['alice_cred_revoc_id'], rev_reg_delta_json) = \
        await anoncreds.issuer_create_credential(carrier_a['wallet'], carrier_a['cc_cred_offer'],
                                                 carrier_a['cc_cred_request'],
                                                 carrier_a['alice_cc_cred_values'],
                                                 carrier_a['rev_reg_id'],
                                                 tails_reader)
    # Note that in the above, revocation registry data is passed to issue the credential

    # Issuer Posts Revocation Registry Delta to Ledger
    print("Carrier A -> Send revocation registry delta to Ledger")
    await send_revoc_reg_delta(carrier_a['pool'], carrier_a['wallet'], carrier_a['did'],
                               carrier_a['rev_reg_id'], rev_reg_delta_json)

    # Issuer sends credential to Prover
    print("Carrier A -> Send City Card Credential to Alice")
    alice['cc_cred'] = carrier_a['cc_cred']

    # Prover Gets RevocationRegistryDefinition from Ledger
    print("Alice -> Get revocation registry definition from Ledger")
    prover_did = alice['did']
    credential = json.loads(alice['cc_cred'])

    (alice['rev_reg_id'], revoc_reg_def_json) = \
        await get_revoc_reg_def(alice['pool'], prover_did, credential['rev_reg_id'])

    # Prover stores credential and revocation data
    print("Alice -> Store the credential and revocation data")
    _, alice['cc_cred_def'] = await get_cred_def(alice['pool'], alice['did'], alice['cc_cred_def_id'])

    await anoncreds.prover_store_credential(alice['wallet'], None,  # none = cred_id, can be any string I think
                                            alice['cc_cred_request_metadata'],
                                            alice['cc_cred'], alice['cc_cred_def'], revoc_reg_def_json)

    # ---------------------------------- USING THE CREDENTIALS ---------------------------------- #

    print("\n=====================================================================")
    print("== Drive a train with Carrier B - City Card proving ==")

    print("Carrier B -> Create Ticket Check Proof Request")
    nonce = await anoncreds.generate_nonce()
    carrier_b['ticket_check_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Ticket Check',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'city',
                'restrictions': [{'cred_def_id': carrier_a['cc_cred_def_id']}, {'cred_def_id': carrier_b['cc_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'half_price',
                'restrictions': [{'cred_def_id': carrier_a['cc_cred_def_id']}, {'cred_def_id': carrier_b['cc_cred_def_id']}]
            },
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'max_zone',
                'p_type': '>=',
                'p_value': 2,
                'restrictions': [{'cred_def_id': carrier_a['cc_cred_def_id']}, {'cred_def_id': carrier_b['cc_cred_def_id']}]
            }
        },
    })

    print("Carrier B -> Send Ticket Check Proof Request to Alice")
    alice['ticket_check_proof_request'] = carrier_b['ticket_check_proof_request']

    print("Alice -> Get credentials for Ticket Check Proof Request")

    search_handle = await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                            alice['ticket_check_proof_request'], None)

    # get_credential_for_referent = prover_fetch_credentials_for_proof_req
    cred_for_attr1 = await get_credential_for_referent(search_handle, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_handle, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_handle, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_handle, 'attr4_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_handle, 'predicate1_referent')

    creds = [cred_for_attr1, cred_for_attr2, cred_for_attr3, cred_for_attr4, cred_for_predicate1]
    for cred in creds:
        print("[i] Credentials from search")
        print(cred)

    await anoncreds.prover_close_credentials_search_for_proof_req(search_handle)

    alice['creds_for_ticket_check_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                             cred_for_attr2['referent']: cred_for_attr2,
                                             cred_for_attr3['referent']: cred_for_attr3,
                                             cred_for_attr4['referent']: cred_for_attr4,
                                             cred_for_predicate1['referent']: cred_for_predicate1}
    # NOTE: the search returns the same cred (referent) each time, so this dict has one entry that's
    # being readded and is presumably automatically skipped

    # Prover Gets RevocationRegistryDelta from Ledger
    # Prover Creates Revocation State
    # (both are done in prover_get_entities_from_ledger)

    request_time = get_current_time()
    alice['schemas'], alice['cred_defs'], alice['revoc_states'], timestamps = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did'],
                                              alice['creds_for_ticket_check_proof'], alice['name'],
                                              _from_time=alice['last_revoc_update'],
                                              _to_time=request_time,
                                              _tails_reader=tails_reader)
    alice['last_revoc_update'] = request_time

    print("Alice -> Create Ticket Check Proof")
    alice['ticket_check_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Alice',
            'attr2_referent': 'Garcia',
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'],
                               'revealed': True, 'timestamp': timestamps[cred_for_attr3['referent']]},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True,
                               'timestamp': timestamps[cred_for_attr4['referent']]},
        },
        'requested_predicates': {
            'predicate1_referent': {'cred_id': cred_for_predicate1['referent'],
                                    'timestamp': timestamps[cred_for_predicate1['referent']]}
        }
    })

    alice['ticket_check_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['ticket_check_proof_request'],
                                            alice['ticket_check_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("Alice -> Send Ticket Check Proof to Carrier B")
    carrier_b['ticket_check_proof'] = alice['ticket_check_proof']
    ticket_check_proof_object = json.loads(carrier_b['ticket_check_proof'])

    # Debug
    print("[i] Identifiers received from Prover:")
    print(ticket_check_proof_object['identifiers'])
    # Debug: check if timestamps are in there
    for identifier in ticket_check_proof_object['identifiers']:
        assert identifier['timestamp'] is not None
        # Put correct timestamp in the requested credential if this fails.
        # otherwise get_revoc_reg() will fail while verifying

    carrier_b['schemas_for_job_application'], carrier_b['cred_defs_for_job_application'], \
        carrier_b['revoc_reg_defs_for_job_application'], carrier_b['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(carrier_b['pool'], carrier_b['did'],
                                                ticket_check_proof_object['identifiers'], carrier_b['name'])

    print("Carrier B -> Verify Ticket Check Proof from Alice")
    # TODO verify encoding?
    # assert 'Bachelor of Science, Marketing' == \
    #        ticket_check_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    # assert 'graduated' == \
    #        ticket_check_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    # assert '123-45-6789' == \
    #        ticket_check_proof_object['requested_proof']['revealed_attrs']['attr5_referent']['raw']
    #
    # assert 'Alice' == ticket_check_proof_object['requested_proof']['self_attested_attrs']['attr1_referent']
    # assert 'Garcia' == ticket_check_proof_object['requested_proof']['self_attested_attrs']['attr2_referent']
    # assert '123-45-6789' == ticket_check_proof_object['requested_proof']['self_attested_attrs']['attr6_referent']

    ticket_validity = await anoncreds.verifier_verify_proof(carrier_b['ticket_check_proof_request'],
                                                            carrier_b['ticket_check_proof'],
                                                            carrier_b['schemas_for_job_application'],
                                                            carrier_b['cred_defs_for_job_application'],
                                                            carrier_b['revoc_reg_defs_for_job_application'],
                                                            carrier_b['revoc_regs_for_job_application'])
    print("Ticket validity:", ticket_validity)
    assert ticket_validity is True

    print("\n=====================================================================")
    print("== Alice tries to use a Carrier 2 exclusive service ==")

    carrier_b['ex_ticket_check_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Ticket Check',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'city',
                'restrictions': [{'cred_def_id': carrier_a['cc_cred_def_id']}, {'cred_def_id': carrier_b['cc_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'half_price',
                'restrictions': [{'cred_def_id': carrier_a['cc_cred_def_id']}, {'cred_def_id': carrier_b['cc_cred_def_id']}]
            },
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'max_zone',
                'p_type': '>=',
                'p_value': 2,
                'restrictions': [{'cred_def_id': carrier_a['cc_cred_def_id']}, {'cred_def_id': carrier_b['cc_cred_def_id']}]
            }
        },
    })

    print("Carrier B -> Send Exclusive Ticket Check Proof Request to Alice")
    alice['ex_ticket_check_proof_request'] = carrier_b['ex_ticket_check_proof_request']

    print("Alice -> Get credentials for Exclusive Ticket Check Proof Request")
    search_handle = \
        await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                alice['ex_ticket_check_proof_request'], None)

    # get_credential_for_referent = prover_fetch_credentials_for_proof_req
    ex_cred_for_attr1 = await get_credential_for_referent(search_handle, 'attr1_referent')
    ex_cred_for_attr2 = await get_credential_for_referent(search_handle, 'attr2_referent')
    ex_cred_for_attr3 = await get_credential_for_referent(search_handle, 'attr3_referent')
    ex_cred_for_attr4 = await get_credential_for_referent(search_handle, 'attr4_referent')
    ex_cred_for_predicate1 = await get_credential_for_referent(search_handle, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_handle)

    print("Found credential for attribute 1?", 'referent' in ex_cred_for_attr1)
    print("Found credential for attribute 2?", 'referent' in ex_cred_for_attr2)
    print("Found credential for attribute 3?", 'referent' in ex_cred_for_attr3)
    print("Found credential for attribute 4?", 'referent' in ex_cred_for_attr4)
    print("Found credential for predicate 1?", 'referent' in ex_cred_for_predicate1)
    # 1,2 and 6 are found because they have no restrictions
    print("Alice -> Can't find matching credentials. Attempt to use card from Carrier A anyway")

    alice['creds_for_ex_ticket_check_proof'] = {ex_cred_for_attr1['referent']: ex_cred_for_attr1}

    request_time = get_current_time()
    alice['schemas'], alice['cred_defs'], alice['revoc_states'], timestamps = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did'],
                                              alice['creds_for_ex_ticket_check_proof'], alice['name'],
                                              _from_time=alice['last_revoc_update'],
                                              _to_time=request_time,
                                              _tails_reader=tails_reader)
    alice['last_revoc_update'] = request_time

    print("Alice -> Create Ticket Check Proof")
    alice['ex_ticket_check_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Alice',
            'attr2_referent': 'Garcia',
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': ex_cred_for_attr1['referent'],
                               'revealed': True, 'timestamp': timestamps[ex_cred_for_attr1['referent']]},
            'attr4_referent': {'cred_id': ex_cred_for_attr1['referent'], 'revealed': True,
                               'timestamp': timestamps[ex_cred_for_attr1['referent']]},
        },
        'requested_predicates': {
            'predicate1_referent': {'cred_id': ex_cred_for_attr1['referent'],
                                    'timestamp': timestamps[ex_cred_for_attr1['referent']]}
        }
    })

    alice['ex_ticket_check_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['ex_ticket_check_proof_request'],
                                            alice['ex_ticket_check_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("Alice -> Send Exclusive Ticket Check Proof to Carrier B")
    carrier_b['ex_ticket_check_proof'] = alice['ex_ticket_check_proof']
    ex_ticket_check_proof_object = json.loads(carrier_b['ex_ticket_check_proof'])

    carrier_b['schemas_for_job_application'], carrier_b['cred_defs_for_job_application'], \
        carrier_b['revoc_reg_defs_for_job_application'], carrier_b['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(carrier_b['pool'], carrier_b['did'],
                                                ex_ticket_check_proof_object['identifiers'], carrier_b['name'])

    print("Carrier B -> Verify Exclusive Ticket Check Proof from Alice")
    try:
        ticket_validity = await anoncreds.verifier_verify_proof(carrier_b['ex_ticket_check_proof_request'],
                                                                carrier_b['ex_ticket_check_proof'],
                                                                carrier_b['schemas_for_job_application'],
                                                                carrier_b['cred_defs_for_job_application'],
                                                                carrier_b['revoc_reg_defs_for_job_application'],
                                                                carrier_b['revoc_regs_for_job_application'])
    except IndyError as ex:
        print("Exception occured:", errorcode_to_exception(ex.error_code))

    print("\n=====================================================================")
    print("== Carrier A revokes Alice's card ==")

    print("Carrier A -> Revoke proof")
    rev_reg_delta_json = await anoncreds.issuer_revoke_credential(carrier_a['wallet'], tails_reader,
                                                                  carrier_a['rev_reg_id'],
                                                                  carrier_a['alice_cred_revoc_id'])

    print("Carrier A -> Send revocation registry delta to Ledger")
    await send_revoc_reg_delta(carrier_a['pool'], carrier_a['wallet'], carrier_a['did'],
                               carrier_a['rev_reg_id'], rev_reg_delta_json)

    print("\n=====================================================================")
    print("== Alice tries to use revoked card ==")
    time.sleep(1)

    # the proof request is the same, so alice uses her cached credential search results
    # to make new proof (alice['creds_for_ticket_check_proof'])
    print("Alice -> Reuse cached credential request and the credentials she used last time")

    # Alice updates her data
    print("Alice -> Refresh revocation states and credential timestamps")
    request_time = get_current_time()
    alice['schemas'], alice['cred_defs'], alice['revoc_states'], timestamps = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did'],
                                              alice['creds_for_ticket_check_proof'], alice['name'],
                                              _from_time=alice['last_revoc_update'],
                                              _to_time=request_time,
                                              _tails_reader=tails_reader)
    alice['last_revoc_update'] = request_time

    print("Alice -> Create Ticket Check Proof")
    alice['ticket_check_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Alice',
            'attr2_referent': 'Garcia',
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'],
                               'revealed': True, 'timestamp': timestamps[cred_for_attr3['referent']]},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True,
                               'timestamp': timestamps[cred_for_attr4['referent']]},
        },
        'requested_predicates': {
            'predicate1_referent': {'cred_id': cred_for_predicate1['referent'],
                                    'timestamp': timestamps[cred_for_predicate1['referent']]}
        }
    })

    alice['ticket_check_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['ticket_check_proof_request'],
                                            alice['ticket_check_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("Alice -> Send Ticket Check Proof to Carrier B")
    carrier_b['ticket_check_proof'] = alice['ticket_check_proof']
    ticket_check_proof_object = json.loads(carrier_b['ticket_check_proof'])

    carrier_b['schemas_for_job_application'], carrier_b['cred_defs_for_job_application'], \
        carrier_b['revoc_reg_defs_for_job_application'], carrier_b['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(carrier_b['pool'], carrier_b['did'],
                                                ticket_check_proof_object['identifiers'], carrier_b['name'])

    print("Carrier B -> Verify Ticket Check Proof from Alice: ")
    ticket_validity = await anoncreds.verifier_verify_proof(carrier_b['ticket_check_proof_request'],
                                                            carrier_b['ticket_check_proof'],
                                                            carrier_b['schemas_for_job_application'],
                                                            carrier_b['cred_defs_for_job_application'],
                                                            carrier_b['revoc_reg_defs_for_job_application'],
                                                            carrier_b['revoc_regs_for_job_application'])
    print("Ticket validity:", ticket_validity)
    assert ticket_validity is False

    # ---------------------------------- CLEAN UP ---------------------------------- #

    print("\n=====================================================================")

    print("Sovrin Steward -> Close and Delete wallet")
    await wallet.close_wallet(steward['wallet'])
    await wallet.delete_wallet(steward['wallet_config'], steward['wallet_credentials'])

    print("Government -> Close and Delete wallet")
    await wallet.close_wallet(government['wallet'])
    await wallet.delete_wallet(government['wallet_config'], government['wallet_credentials'])

    print("Carrier A -> Close and Delete wallet")
    await wallet.close_wallet(carrier_a['wallet'])
    await wallet.delete_wallet(carrier_a['wallet_config'], carrier_a['wallet_credentials'])

    print("Carrier B -> Close and Delete wallet")
    await wallet.close_wallet(carrier_b['wallet'])
    await wallet.delete_wallet(carrier_b['wallet_config'], carrier_b['wallet_credentials'])

    print("Alice -> Close and Delete wallet")
    await wallet.close_wallet(alice['wallet'])
    await wallet.delete_wallet(alice['wallet_config'], alice['wallet_credentials'])

    print("Close and Delete pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("Demo finished.")


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


async def create_wallet_and_register_verinym(_steward, recipient):
    await create_wallet(recipient)
    print("{} -> Get Verinym through Steward".format(recipient['name']))

    (recipient['did'], recipient['key']) = await did.create_and_store_my_did(recipient['wallet'], "{}")

    recipient_verkey = recipient['key']
    recipient_role = recipient['role'] or None
    # _steward['info'] = {
    #     'did': recipient['did'],
    #     'verkey': recipient['key'],
    #     'role': recipient['role'] or None
    # }
    await send_nym(_steward['pool'], _steward['wallet'], _steward['did'],
                   new_did=recipient['did'], new_key=recipient_verkey, role=recipient_role)


async def get_credential_for_referent(_search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(_search_handle, referent, 10))
    if len(credentials) == 0:
        return {}
    return credentials[0]['cred_info']


def get_current_time() -> int:
    return int(time.time())


def encode(_input: str) -> str:
    byte_str = _input.encode('utf-8')
    return str(int.from_bytes(byte_str, byteorder='big'))


# ---------  Mass get data from ledger

async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor,
                                          _from_time=None, _to_time=None, _tails_reader=None):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    timestamps = {}  # Timestamps need to be saved to be put in the request proof
    print("{} -> Get data from Ledger:".format(actor))

    for item in identifiers.values():
        print("\t- Schemas")
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\t- Credential Definitions")
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if item['rev_reg_id'] is not None:
            print("\t- Revocation registry delta")
            rev_reg_id = item['rev_reg_id']
            (rev_reg_id, revoc_reg_delta_json, timestamp) = \
                await get_revoc_reg_delta(pool_handle, _did, rev_reg_id, _from_time, _to_time)
            referent = item['referent']
            timestamps[referent] = timestamp
            print("\t[i] Timestamp for", referent, "=", timestamp)
            print("\t- Revocation registry definition")
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
    print("{} -> Get data from Ledger:".format(actor))

    for item in identifiers:
        print("\t- Schemas")
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\t- Credential Definitions")
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if item['rev_reg_id'] is not None:
            print("\t- Revocation registry definition")
            rev_reg_id = item['rev_reg_id']
            (rev_reg_id, revoc_reg_def_json) = await get_revoc_reg_def(pool_handle, _did, rev_reg_id)
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)
            print("\t- Revocation registry")
            timestamp = item['timestamp']
            (rev_reg_id, rev_reg_json, identifier) = await get_revoc_reg(pool_handle, _did, rev_reg_id, timestamp)
            rev_regs[rev_reg_id] = {timestamp: json.loads(rev_reg_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)

await run()
