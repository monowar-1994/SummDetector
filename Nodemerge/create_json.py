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

    tables = mapping_dict.keys()
    psql_connection_url = 'postgresql+pg8000://cpsc538p:12345678@localhost/darpa_tc3_cadets'
    engine = create_engine(psql_connection_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    for table in tables:
        print("Starting for {} table".format(table))
        result = session.execute('SELECT uuid FROM \"'+table+'\"')
        table_uuids = [row[0] for row in result]
        print("{} rows in table {}".format(len(table_uuids), table))
        elementCounter += len(table_uuids)
        for uuid in table_uuids:
            if uuid not in mappingJson.keys():
                mappingJson[uuid] = mapping_dict[table]
            else:
                if mapping_dict[table] != mappingJson[uuid]:
                    print("MISMATCH")
                duplicateCounter += 1
        print("Finished for {} table".format(table))
    session.close()
    
    print("Json elements num: {}".format(len(mappingJson.keys())))
    print("Correct elements num: {}".format(elementCounter))
    print("Duplicate counter: {}".format(duplicateCounter))
    
    with open("index_file.json", "w") as outputFile:
        json.dump(mappingJson, outputFile)
createJson()