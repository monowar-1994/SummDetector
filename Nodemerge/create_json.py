import db_classes as orm
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from sqlalchemy import select
import pg8000
import json


def createJson():
    elementCounter = 0
    duplicateCounter = 0
    mappingJson = {}
    mapping_dict = {
        "Host": 2,
        "Principal": 3,
        "Subject": 4,
        "FileObject": 5,
        "UnnamedPipeObject": 6,
        "NetflowObject": 8,
        "SrcSinkObject": 9,
        "RegistryKeyObject": 12}
    
    offset_dict = {
        "Host": 0,
        "Principal": 3,
        "Subject": 67,
        "FileObject": 224696,
        "UnnamedPipeObject": 2728098,
        "NetflowObject": 2784773,
        "SrcSinkObject": 2940095,
        "RegistryKeyObject": 3053445}

    tables = mapping_dict.keys()
    psql_connection_url = 'postgresql+pg8000://cpsc538p:12345678@localhost/darpa_tc3_cadets'
    engine = create_engine(psql_connection_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    for table in tables:
        print("Starting for {} table".format(table))
        result = session.execute('SELECT id, uuid FROM \"'+table+'\"')
        table_id_uuids = [(row[0], row[1]) for row in result]
        print("{} rows in table {}".format(len(table_id_uuids), table))
        elementCounter += len(table_id_uuids)
        for id_uuid in table_id_uuids:
            if id_uuid[1] not in mappingJson.keys():
                mappingJson[id_uuid[1]] = [ mapping_dict[table], id_uuid[0]+offset_dict[table] ]
            else:
                if mapping_dict[table] != mappingJson[id_uuid[1]]:
                    print("MISMATCH")
                duplicateCounter += 1
        print("Finished for {} table".format(table))
    session.close()
    
    print("Json elements num: {}".format(len(mappingJson.keys())))
    print("Correct elements num: {}".format(elementCounter))
    print("Duplicate counter: {}".format(duplicateCounter))
    
    with open("index_file.json", "w") as outputFile:
        json.dump(mappingJson, outputFile, indent=4, separators=(',', ': '))

createJson()