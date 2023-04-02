import db_classes as orm
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from sqlalchemy import select
import pg8000
import json

def findReadOnlyFiles():
    # Set up the connection
    psql_connection_url = 'postgresql+pg8000://cpsc538p:12345678@localhost/darpa_tc3_cadets'
    engine = create_engine(psql_connection_url)
    Session = sessionmaker(bind=engine)
    session = Session()

    # number_of_events = session.query(func.count(orm.Event.id)).scalar()
    # number_of_subjects = session.query(func.count(orm.Subject.id)).scalar()
    # number_of_files = session.query(func.count(orm.FileObject.id)).scalar()
    # print(number_of_events, number_of_subjects, number_of_files)
    skeleton_update_query = 'UPDATE \"FileObject\" set readonly=0 WHERE uuid = \'{}\';'
    result = session.execute('SELECT * FROM \"Event\" WHERE type = \'EVENT_WRITE\' ')
    batch_size = 10000
    count = 1
    batch_count = 0
    loaded_result = result.fetchall()
    print("Number of candidate_rows: {}".format(len(loaded_result)))
    final_execute_query = ''
    for result in loaded_result:
        predicate_object1 = result.predicate_object
        predicate_object2 = result.predicate_object_2
        
        if count%batch_size == 0:
            session.execute(final_execute_query)
            session.commit()
            batch_count += 1
            print("Update complete for a batch: {}.".format(batch_count))
            final_execute_query = ''
        else:
            if predicate_object1 is not None:
                final_execute_query += skeleton_update_query.format(predicate_object1)
            if predicate_object2 is not None:   
                final_execute_query += skeleton_update_query.format(predicate_object2)
            count +=1 

    session.execute(final_execute_query)
    session.commit()
    batch_count += 1
    print("Update complete for final batch: {}.".format(batch_count))

    session.close()

findReadOnlyFiles()