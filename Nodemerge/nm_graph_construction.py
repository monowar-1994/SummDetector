import os
import json
import db_classes as orm
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pg8000
import networkx as nx
import pickle

connection_url = 'postgresql+pg8000://cpsc538p:12345678@localhost/darpa_tc3_cadets'
total_event_count = 41350895
index_file_location = 'Nodemerge/index_file.json'

benign_time_limit = 1523028000000000000
training_graph = nx.MultiDiGraph()
testing_graph = nx.MultiDiGraph()


training_graph_path = '/home/anjumm1/538P/SummDetector/Nodemerge/Training_graphs'
testing_graph_path = '/home/anjumm1/538P/SummDetector/Nodemerge/Testing_graphs'



def batched_event_load( session, start_idx, end_idx, graph, flag = 0):
    if flag == 0:
        skeleton_query = 'select uuid, subject, type, predicate_object, predicate_object_2 from \"Event\" where id>={} and id < {} and time_stamp_nanos< 1523028000000000000;'.format(start_idx, end_idx)
    else:
        skeleton_query = 'select uuid, subject, type, predicate_object, predicate_object_2 from \"Event\" where id>={} and id < {} and time_stamp_nanos>=1523028000000000000;'.format(start_idx, end_idx)
    objects = session.execute(skeleton_query)
    results = objects.fetchall()
    for r in results:
        e_id = r[0]
        subject_id = r[1]
        e_type = r[2]
        predicate_obj1 = r[3]
        predicate_obj2 = r[4]

        try:
            if predicate_obj1 is not None:
                graph.add_edge(subject_id, predicate_obj1, event_type = e_type, key =  e_id)
            if predicate_obj2 is not None:
                graph.add_edge(subject_id, predicate_obj2, event_type = e_type, key =  e_id)
        except Exception:
            print(e_id, subject_id, e_type, predicate_obj1, predicate_obj2)

def execute(batch_size = 1000000, _flag = 0):
    engine = create_engine(connection_url)
    Session = sessionmaker(bind=engine)
    session = Session()
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
        nx.write_edgelist(graph, open(full_path, "wb"))
        count+=1
        print("Dump Complete for Graph: {}".format(str(count)))

# execute(_flag=0)
# relevant_train_graphs = get_graphs(training_graph)
# dump_graphs(relevant_train_graphs, training_graph_path)

execute(_flag=1)
relevant_test_graphs = get_graphs(testing_graph)
dump_graphs(relevant_test_graphs, testing_graph_path)
