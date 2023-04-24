import os
import json
import db_classes as orm
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pg8000
import networkx as nx
import pickle
import base64

connection_url = 'postgresql+pg8000://cpsc538p:12345678@localhost/darpa_tc3_cadets'
total_event_count = 41350895
index_file_location = '/home/anjumm1/538P/SummDetector/Nodemerge/index_file.json'

benign_time_limit = 1523028000000000000
training_graph = nx.MultiDiGraph()
testing_graph = nx.MultiDiGraph()


training_graph_path = '/scratch/cadet_graphs_attr/Training_Graphs'
testing_graph_path = '/scratch/cadet_graphs_attr/Testing_Graphs'

begin_time_nanos = 1522706861813350340


def get_encoded_string(path_string):
    a = base64.b64encode(path_string.encode('ascii'))
    return a.decode('ascii')

def get_decoded_path(base64_encoded_path):
    a = base64.b64decode(base64_encoded_path.encode('ascii'))
    return a.decode('ascii')


def batched_event_load( session, start_idx, end_idx, graph, flag = 0):
    if flag == 0:
        skeleton_query = 'select id, subject, type, predicate_object, predicate_object_2, time_stamp_nanos, prediacte_object_path, predicate_object_path_2 from \"Event\" where id>={} and id < {} and time_stamp_nanos< 1523028000000000000;'.format(start_idx, end_idx)
    else:
        skeleton_query = 'select id, subject, type, predicate_object, predicate_object_2, time_stamp_nanos, prediacte_object_path, predicate_object_path_2 from \"Event\" where id>={} and id < {} and time_stamp_nanos>=1523028000000000000;'.format(start_idx, end_idx)
    objects = session.execute(skeleton_query)
    results = objects.fetchall()
    for r in results:
        e_id = r[0]
        subject_id = r[1]
        e_type = r[2]
        predicate_obj1 = r[3]
        predicate_obj2 = r[4]
        time_stamp = r[5]
        predicate_object_path1 = r[6]
        predicate_object_path2 = r[7]
        
        if predicate_object_path1 is not None:
            if predicate_object_path1=='<unknown>' or len(predicate_object_path1.strip()) == 0:
                predicate_object_path1 = ''
            else:
                predicate_object_path1 = '{}'.format(get_encoded_string(predicate_object_path1))

        if predicate_object_path2 is not None:
            if predicate_object_path2=='<unknown>' or len(predicate_object_path2.strip()) == 0:
                predicate_object_path2 = ''
            else:
                predicate_object_path2 = '{}'.format(get_encoded_string(predicate_object_path2))

        if subject_id is not None:

            subject_info = get_info(subject_id)
            if subject_info is None:
                continue
            s_id = subject_info[1]
            s_type = 4

            if time_stamp is not None:
                logical_timestamp = time_stamp - begin_time_nanos
            else:
                logical_timestamp = 0

            try:
                if predicate_obj1 is not None:
                    predicate_obj1_info = get_info(predicate_obj1)
                    if predicate_obj1_info is not None:
                        if predicate_obj1_info[0] == 5:
                            graph.add_edge(s_id, predicate_obj1_info[1] , source_type = s_type, dest_type = predicate_obj1_info[0], event_type = e_type, timestamp = logical_timestamp, event_id = e_id, attr = predicate_object_path1)
                        elif predicate_obj1_info[0] == 8:
                            graph.add_edge(s_id, predicate_obj1_info[1] , source_type = s_type, dest_type = predicate_obj1_info[0], event_type = e_type, timestamp = logical_timestamp, event_id = e_id, attr = get_socket_address(predicate_obj1))
                        else:
                            graph.add_edge(s_id, predicate_obj1_info[1] , source_type = s_type, dest_type = predicate_obj1_info[0], event_type = e_type, timestamp = logical_timestamp, event_id = e_id)

                
                if predicate_obj2 is not None:
                    predicate_obj2_info = get_info(predicate_obj2)
                    if predicate_obj2_info is not None:
                        if predicate_obj2_info[0] == 5:
                            graph.add_edge(s_id, predicate_obj2_info[1] , source_type = s_type, dest_type = predicate_obj2_info[0], event_type = e_type, timestamp = logical_timestamp, event_id = e_id, attr=predicate_object_path2)
                        elif predicate_obj2_info[0] == 8:
                            graph.add_edge(s_id, predicate_obj2_info[1] , source_type = s_type, dest_type = predicate_obj2_info[0], event_type = e_type, timestamp = logical_timestamp, event_id = e_id, attr=get_socket_address(predicate_obj2))
                        else:
                            graph.add_edge(s_id, predicate_obj2_info[1] , source_type = s_type, dest_type = predicate_obj2_info[0], event_type = e_type, timestamp = logical_timestamp, event_id = e_id)

            except Exception:
                print(e_id, subject_id, e_type, predicate_obj1, predicate_obj2)


def get_socket_address(uuid):
    if uuid not in socket_information:
        return ''    
    return '{}:{}'.format(socket_information[uuid][0], socket_information[uuid][1])

def get_socket_info(session):
    socket_map = dict()
    skeleton_query = 'Select uuid, local_address, remote_address from \"NetflowObject\";'
    resultset = session.execute(skeleton_query)
    results = resultset.fetchall()
    for result in results:
        uuid = result[0]
        local_ip = result[1]
        remote_ip = result[2]
        if local_ip.lower() == 'localhost' or local_ip == '::1':
            local_ip = '127.0.0.1'
        if remote_ip.lower() == 'localhost' or remote_ip == '::1':
            remote_ip = '127.0.0.1'

        if uuid not in socket_map:
            socket_map[uuid] = [local_ip, remote_ip]
    
    return socket_map


def get_info(uuid):
    if uuid in db_idx:
        return db_idx[uuid]
    return None

def load_index(index_file_location):
    fp = open(index_file_location, 'r')
    return json.load(fp)

def execute(batch_size = 1000000, _flag = 0):
    global db_idx
    global socket_information
    db_idx = load_index(index_file_location)
    engine = create_engine(connection_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    socket_information = get_socket_info(session)
    count = 0
    batch_count = 0
    while count<total_event_count:
        if _flag ==0: 
            batched_event_load(session, count, count+batch_size, training_graph, flag = _flag)
        else:
            batched_event_load(session, count, count+batch_size, testing_graph, flag = _flag)
        count += batch_size
        batch_count +=1
        print("Batched Execution Complete for Batch: {}".format(batch_count))

def get_graphs(original_graph):
    return_graphs = []
    wcc_components = nx.algorithms.weakly_connected_components(original_graph)
    component_list = list(wcc_components)
    count = 0
    for component in component_list:
        list_of_nodes_in_the_component = list(component)
        number_of_nodes = len(list_of_nodes_in_the_component)
        count+=1
        print("Component Number: {} , Number of Nodes: {}".format(count, number_of_nodes))
        if number_of_nodes>5:
            temp_graph = original_graph.subgraph(list_of_nodes_in_the_component)
            temp_graph_num_nodes = temp_graph.number_of_nodes()
            temp_graph_num_edges = temp_graph.number_of_edges()
            print("Temporary Train Graph Found, Number of Nodes: {}, Number of Edges: {}".format(temp_graph_num_nodes, temp_graph_num_edges))
            return_graphs.append(temp_graph)
    return return_graphs




def dump_graphs(graph_list, destination_dir):
    count = 0
    for graph in graph_list:
        name = 'graph_'+str(count)+'.edgelist'
        full_path = os.path.join(destination_dir, name)
        nx.write_edgelist(graph, open(full_path, 'wb'))
        # pickle.dump(graph, open(full_path, "wb"))
        count+=1
        print("Dump Complete for Graph: {}".format(str(count)))

execute(_flag=0)
relevant_train_graphs = get_graphs(training_graph)
dump_graphs(relevant_train_graphs, training_graph_path)

# execute(_flag=1)
# relevant_test_graphs = get_graphs(testing_graph)
# dump_graphs(relevant_test_graphs, testing_graph_path)
