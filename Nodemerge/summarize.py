import db_classes as orm
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from sqlalchemy import select
import os
import json
import argparse
import networkx as nx
from operator import itemgetter
import base64
import pandas as pd
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import fpgrowth, association_rules


CADET = 1
THEIA = 2

mapping_dict = {
    "Host": 2,
    "Principal": 3,
    "Subject": 4,
    "FileObject": 5,
    "UnnamedPipeObject": 6,
    "NetflowObject": 8,
    "SrcSinkObject": 9,
    "RegistryKeyObject": 12,
    2: "Host",
    3: "Principal",
    4: "Subject",
    5: "FileObject",
    6: "UnnamedPipeObject",
    8: "NetflowObject",
    9: "SrcSinkObject",
    12: "RegistryKeyObject"
}

template_types = {
    "FILE": 13,
    "SOCKET": 14,
    13: "FILE",
    14: "SOCKET"
}


cadet_offset_dict = {
    "Host": 0,
    "Principal": 3,
    "Subject": 67,
    "FileObject": 224696,
    "UnnamedPipeObject": 2728098,
    "NetflowObject": 2784773,
    "SrcSinkObject": 2940095,
    "RegistryKeyObject": 3053445
}

def get_encoded_string(path_string):
    a = base64.b64encode(path_string.encode('ascii'))
    return a.decode('ascii')

def get_decoded_path(base64_encoded_path):
    a = base64.b64decode(base64_encoded_path.encode('ascii'))
    return a.decode('ascii')

def get_and_prune_the_input_graph(graph_file_location):
    graph = nx.read_edgelist(
        graph_file_location, nodetype=int, data=True, create_using=nx.MultiDiGraph)
    edge_set = graph.edges(data=True)
    pruned_graph_edge_set = set()
    for edge in edge_set:
        temp_edge_tuple = (edge[0], edge[1], edge[2]['source_type'], edge[2]
                           ['dest_type'], edge[2]['event_type'], edge[2]['timestamp'])
        pruned_graph_edge_set.add(temp_edge_tuple)
    pruned_graph = nx.MultiDiGraph()
    for edge in pruned_graph_edge_set:
        pruned_graph.add_edge(edge[0], edge[1], source_type=edge[2],
                              dest_type=edge[3], event_type=edge[4], timestamp=edge[5])
    return graph, pruned_graph


def get_indices(index_file_location, reverse_index_file_location):
    global index
    global reverse_idx
    index = json.load(index_file_location)
    print("Index Loaded.")
    reverse_idx = json.load(reverse_index_file_location)
    print("Reverse Index Loaded")


def get_timestamp_map(pruned_graph):
    timestamp_map = dict()
    pruned_edge_set = pruned_graph.edges(data=True)
    for edge in pruned_edge_set:
        if edge[2]['event_type'] == 'EVENT_FORK':
            subject_id = edge[0]
            object_id = edge[1]
            if reverse_idx[str(object_id)][0] != 4:
                miss_count += 1
                continue
            start_time = edge[2]["timestamp"]
            timestamp_map[object_id] = start_time
    return timestamp_map


def get_read_only_status(session):
    read_only_status = dict()
    read_statuses = session.execute(
        "Select uuid, readonly from \"FileObject\";").fetchall()
    for status in read_statuses:
        if status[0] not in read_only_status:
            read_only_status[status[0]] = status[1]

    return read_only_status


def get_file_access_pattern(timestamp_map, pruned_graph_edges, read_only_dict, debug=False):
    file_access_pattern = dict()
    for process_id in timestamp_map:
        file_access_pattern[process_id] = list()

    count = 0
    another_count = 0
    for edge in pruned_graph_edges:
        subject_id = edge[0]
        object_id = edge[1]
        event_type = edge[2]["event_type"]
        timestamp = edge[2]["timestamp"]
        if event_type == "EVENT_OPEN" or event_type == "EVENT_READ" or event_type == "EVENT_CLOSE" or event_type == "EVENT_MMAP":
            if str(object_id) in reverse_idx:
                another_count += 1
                object_info = reverse_idx[str(object_id)]

                if object_info[0] == 5:
                    read_only_value = read_only_dict[object_info[1]]
                    if read_only_value == 1:
                        if subject_id in file_access_pattern:
                            file_access_pattern[subject_id].append(
                                (object_id, timestamp))
                        else:
                            file_access_pattern[subject_id] = [
                                (object_id, timestamp)]
            else:
                count += 1
    if debug:
        print("Could not find reverse index of {} objects. Good ones: {}".format(
            count, another_count))

    return file_access_pattern


def get_pruned_file_access_pattern(file_access_pattern, timestamp_map ,debug=False):
    pruned_file_access_patterns = dict()
    count = 0
    for key in file_access_pattern:
        curr_fap = file_access_pattern[key]
        curr_fap.sort(key=itemgetter(1))
        if key in timestamp_map:
            start_time_stamp_nanos = timestamp_map[key]
        else:
            count += 1
            continue

        limit = start_time_stamp_nanos + 1000000000  # 1 second limit
        temp = list()
        for item in curr_fap:
            if item[1] < limit:
                temp.append((item[0]))

        pruned_file_access_patterns[key] = temp
    if debug:
        print("Total key not found in timestamp map: {}".format(count))

    return pruned_file_access_patterns

def learn_rof_templates(read_only_dict, timestamp_map, pruned_graph, debug_info = False):
    faps = get_file_access_pattern(timestamp_map, pruned_graph.edges(data=True), read_only_dict, debug = debug_info)
    pruned_faps = get_pruned_file_access_pattern(faps, timestamp_map, debug = debug_info)
    dataset = [pruned_faps[key] for key in pruned_faps]
    te = TransactionEncoder()
    te_ary = te.fit(dataset).transform(dataset)
    df = pd.DataFrame(te_ary, columns = te.columns_)
    frequent_itemset = fpgrowth(df, min_support=0.5, use_colnames=True)

    templates = dict()
    template_node_idx = 4053445

    for index, row in frequent_itemset.iterrows():
        temp_itemset = list(row['itemsets'])
        if len(temp_itemset)>1:
            templates[template_node_idx] = temp_itemset
            template_node_idx+=1

    return templates

def get_template_order(template_dict):
    # we need to sort the templates from the largest to the smallest ones
    sorted_templates = list()
    for key in template_dict:
        sorted_templates.append((key, len(template_dict[key])))
    sorted_templates.sort(key=lambda x: -x[1]) # Sorting in place and in reverse order. 
    return sorted_templates

def check_flags(flag_dict):
    for item in flag_dict:
        if flag_dict[item] == False:
            return False
    return True

def reset_flags(flag_dict):
    for item in flag_dict:
        flag_dict[item] = False

def get_average(timestamps):
    sum = 0
    for timestamp in timestamps:
        sum += timestamp
    avg = sum//len(timestamps)
    return avg

def get_common_filepath(holder):
    actual_file_paths = list()
    for item in holder:
        if "attr" in item[2]:
            file_path = get_decoded_path(item[2]["attr"])
            if file_path.startswith("./"):
                actual_file_paths.append(file_path[1:])
            elif os.path.isabs(file_path) == False:
                actual_file_paths.append(os.path.join("/", file_path))
            else:
                actual_file_paths.append(file_path)

    try:
        common_path = os.path.commonpath(actual_file_paths)
    except:
        common_path = "/"

    return common_path    

def match_file_pattern(sequence, template, template_id):
    # template should be a set (Second Parameter)
    # sequence should be list of outgoing edges of a process node sorted in the timestamp order (First Parameter)
    return_sequence = list()

    idx = 0
    count = len(sequence)
    flags = dict()
    timestamps = list()
    temp_holder = list()

    for item in template:
        flags[item] = False

    while idx<count:
        if sequence[idx][1] not in template:
            template_match_flag = check_flags(flags)
            if template_match_flag:
                property_dict = dict()
                property_dict["source_type"] = 4
                property_dict["dest_type"] = template_types["FILE"] # This is the type of the template of 
                property_dict["event_type"] = "EVENT_READ"
                property_dict["timestamp"] = get_average(timestamps)
                property_dict["attr"] = get_common_filepath(temp_holder)
                data = (sequence[idx][0], template_id, property_dict)
                return_sequence.append(data)
            else: # If we did not find a template
                for item in temp_holder:
                    return_sequence.append(item)
            
            temp_holder.clear()
            reset_flags(flags)
            timestamps.clear()

            return_sequence.append(sequence[idx])
            idx+=1
        else:
            temp_holder.append(sequence[idx])
            timestamps.append(sequence[idx][2]["timestamp"])
            flags[sequence[idx][1]] = True
            idx+=1

    return return_sequence

def summarize(templates, sorted_order, graph, process_nodes, debug = False):
    summarized_graph = nx.MultiDiGraph()
    for node in process_nodes:
        outgoing_edges = graph.out_edges(node, data= True)
        list_of_outgoing_edges = list(outgoing_edges)
        if len(list_of_outgoing_edges) == 0:
            continue
        sorted_list_of_outgoing_edges = sorted(list_of_outgoing_edges, key=lambda x: x[2]['timestamp'])
        temp_list = list(sorted_list_of_outgoing_edges)
        # Reminder: Sorted order is a list
        for template_key in sorted_order:
            actual_template = templates[template_key[0]]
            compressed_list_of_outgoing_edges = match_file_pattern(temp_list, actual_template, template_key[0])
            temp_list = list(compressed_list_of_outgoing_edges)


def learn(graph_file, index_file, ridx_file, database_type, learn_templates, use_templates):
    get_indices(index_file, ridx_file)
    original_graph, pruned_graph = get_and_prune_the_input_graph(graph_file)
    timestamp_map = get_timestamp_map(pruned_graph)

    if database_type == CADET:
        psql_connection_url = 'postgresql+pg8000://cpsc538p:12345678@localhost/darpa_tc3_cadets'
    elif database_type == THEIA:
        psql_connection_url = 'postgresql+pg8000://cpsc538p:12345678@localhost/darpa_tc3_theia'
    else:
        print("Database not specified. Exiting now.")
        exit(8)

    engine = create_engine(psql_connection_url)
    Session = sessionmaker(bind=engine)
    session = Session()

    read_only_status = get_read_only_status(session)
    if learn_templates:
        templates = learn_rof_templates(read_only_status, timestamp_map, pruned_graph, debug_info= False)
        sorted_templates = get_template_order(templates)
    if use_templates:
        pass

    pruned_node_set = pruned_graph.nodes()
    process_nodes = [node for node in pruned_node_set if reverse_idx[str(node)][0] == 4]


    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='nodemerge-summarizer', description="Nodemerge Implementation (CCS 2018)")
    parser.add_argument('graph_filename')
    parser.add_argument('--learn-templates', action='store_true')
    parser.add_argument('--use-templates', action='store_true')
    parser.add_argument('-to', '--template-order',
                        help='Json file that contains the list of the templates in sortted order.')
    parser.add_argument('-td', '--template-dict',
                        help='Json file that contains the template dictionry')
    parser.add_argument('-idx', '--index-file',
                        help='Location of the index file to reduce computation time.')
    parser.add_argument('-ridx', '--reverse-index-file',
                        help='Loaction of the reverse index file to reduce computation time.')
    parser.add_argument('-cfg', '--config-file',
                        help='Json file that holds all the configuration information. If you dont have index or reverse index info, you must add the config file location where it is listed.')
    parser.add_argument('--cadets', action='store_true')
    # Note that this should be removed in later version in favor of list based parsing
    parser.add_argument('--theia', action='store_true')

    args = parser.parse_args()

    graph_filename = args.graph_filename
    learn_template = args.learn_templates
    use_template = args.use_templates
    config_file = args.config_file
    index_file = args.index_file
    reverse_index_file = args.reverse_index_file
    is_cadet = args.cadets
    is_theia = args.theia

    if index_file is None and reverse_index_file is None:
        if config_file is None:
            print("No index and reverse index file provided. Please specify the config file which contains the information.")
            exit(4)
    else:
        if config_file is None:
            if index_file is None and reverse_index_file is not None:
                print("Missing index file location. Please specify that in the command line or just the use the config file for all operations.")
                exit(5)
            elif index_file is not None and reverse_index_file is None:
                print("Reverse index file location is missing. Please specify that in the command line or just use the config file for all operations.")
                exit(6)

    if learn_template and not use_template:
        # do some staff
        pass
    elif use_template and not learn_template:
        template_order_file = args.template_order
        template_dictionary_file = args.template_dict
        if template_order_file is None:
            print("Please provide the absolute file path of the sorted templates.")
            exit(2)
        if template_dictionary_file is None:
            print("Please provide the absoluet file path of the templated dictionary.")
            exit(3)
        # start summarization from here.
    else:
        print("Use template is {} while learn template is {}".format(
            use_template, learn_template))
        exit(1)
