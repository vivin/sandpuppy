import os
import sys
import re
import numpy as np
import pandas as pd

import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

from sklearn.decomposition import PCA
from sklearn.decomposition import NMF
from sklearn.cluster import DBSCAN, OPTICS
from hdbscan import HDBSCAN

from collections import Counter


HOME = os.path.expanduser("~")
BASEPATH = "{HOME}/Projects/phd".format(HOME=HOME)
RESULTS = "{BASEPATH}/results".format(BASEPATH=BASEPATH)

NUM_MALLOCS = 0
NUM_CALLOCS = 1
NUM_FREES = 2
NUM_UNIQUE_SIZES = 3
NUM_UNIQUE_ADDRS = 4
NUM_FAILED_ALLOCS = 5

NUM_FEATURES_PER_BB = 6


def main():

    clustering_methods = ["dbscan", "optics", "hdbscan"]
    bb_feature_options = ["without_bb", "with_bb", "with_bb_call_order"]

    if len(sys.argv) < 5:
        print(sys.argv[0], "<experiment-name> <program-name> without_bb|with_bb|with_bb_call_order dbscan|optics|hdbscan")
        exit(-1)

    experiment_name = sys.argv[1]
    program_name = sys.argv[2]
    bb_features = sys.argv[3]
    clustering_method = sys.argv[4]

    if bb_features not in bb_feature_options:
        sys.exit("Invalid bb feature option: {bb_features}".format(bb_features=bb_features))

    if clustering_method not in clustering_methods:
        sys.exit("Invalid clustering method: {clustering_method}".format(clustering_method=clustering_method))

    experiment_results_directory = "{RESULTS}/{experiment_name}/{program_name}".format(
        RESULTS=RESULTS,
        experiment_name=experiment_name,
        program_name=program_name
    )
    if not os.path.isdir(experiment_results_directory):
        sys.exit("Could not find experiments results directory {experiment_results_directory}.".format(
            experiment_results_directory=experiment_results_directory
        ))

    fuzz_output_directory = "{experiment_results_directory}/fuzz".format(
        experiment_results_directory=experiment_results_directory
    )
    if not os.path.isdir(fuzz_output_directory):
        sys.exit("Could not find afl-fuzz output directory {fuzz_output_directory}>".format(
            fuzz_output_directory=fuzz_output_directory
        ))

    input_queue_directory = "{fuzz_output_directory}/queue".format(
        fuzz_output_directory=fuzz_output_directory
    )

    print("Experiment:", experiment_name)
    print("Program:", program_name)
    print("Basic-block features:", bb_features)
    print("Clustering algorithm:", clustering_method, "\n")

    print("Vectorizing traces...", end="")

    if bb_features == "with_bb" or bb_features == "with_bb_call_order":
        with_call_order = (bb_features == "with_bb_call_order")
        result = vectorize_traces_with_bb(input_queue_directory, with_call_order=with_call_order)
        trace_vectors = result["trace_vectors"]
        basic_blocks = result["basic_blocks"]
        basic_block_transitions = result["basic_block_transitions"]

        index_to_bb = {}
        for bb in basic_blocks.keys():
            index_to_bb[basic_blocks[bb]] = bb

        columns = []
        for i in range(0, len(basic_blocks.keys())):
            columns += [
                "num_mallocs.{bb}".format(bb=index_to_bb[i]),
                "num_callocs.{bb}".format(bb=index_to_bb[i]),
                "num_frees.{bb}".format(bb=index_to_bb[i]),
                "num_unique_sizes.{bb}".format(bb=index_to_bb[i]),
                "num_unique_addresses.{bb}".format(bb=index_to_bb[i]),
                "num_failed_allocations.{bb}".format(bb=index_to_bb[i])
            ]

        index_to_bb_transition = {}
        for bb_transition in basic_block_transitions.keys():
            index_to_bb_transition[basic_block_transitions[bb_transition]] = bb_transition

        if with_call_order:
            for i in range(0, len(basic_block_transitions.keys())):
                columns.append(index_to_bb_transition[i])

    else:
        trace_vectors = vectorize_traces_without_bb(input_queue_directory)
        columns = [
            "num_mallocs",
            "num_callocs",
            "num_frees",
            "num_unique_sizes",
            "num_unique_addresses",
            "num_failed_allocations"
        ]

    print("done")
    print("Vectorized", len(trace_vectors), "traces.\n")

    numpy_trace_vectors = np.array(trace_vectors)
    traces_df = pd.DataFrame(
        data=numpy_trace_vectors,
        columns=columns
    )

    # Normalize vectors
    traces_array = traces_df.to_numpy()
    normalized_traces_array = (traces_array - traces_array.min()) / (traces_array.max() - traces_array.min())

    # Do PCA to project vectors down to 2 and 3 dimensions
    print("Performing PCA (2d)...", end="")
    pca_2d = pca(2, normalized_traces_array)
    print("done")

    print("Performing PCA (3d)...", end="")
    pca_3d = pca(3, normalized_traces_array)
    print("done")

    print("Performing NMF (2d)...", end="")
    nmf_2d = nmf(2, normalized_traces_array)
    print("done")

    print("Performing NMF (3d)...", end="")
    nmf_3d = nmf(3, normalized_traces_array)
    print("done\n")

    # Plot vectors after PCA and NMF
    fig = plt.figure(figsize=(20, 10))

    fig.suptitle("{experiment_name} - {program_name} using {clustering_method} (features: {bb_features})".format(
        experiment_name=experiment_name,
        program_name=program_name,
        bb_features=bb_features,
        clustering_method=clustering_method
    ))

    # 2D projections and clustering

    ax_pca_2d = fig.add_subplot(2, 4, 1)
    ax_pca_2d.set_title("PCA")
    ax_pca_2d.plot(pca_2d[0], pca_2d[1], 'o', markeredgecolor='k')

    ax_nmf_2d = fig.add_subplot(2, 4, 2)
    ax_nmf_2d.set_title("NMF")
    ax_nmf_2d.plot(nmf_2d[0], nmf_2d[1], 'o', markeredgecolor='k')

    print("Clustering 2d PCA projection...", end="")
    ax_pca_2d_clustered = fig.add_subplot(2, 4, 5)
    cluster_plot(
        ax_pca_2d_clustered,
        pca_2d,
        clustering_method,
        "PCA {clustering_method}".format(clustering_method=clustering_method),
        '2d'
    )
    print("done")

    print("Clustering 2d NMF projection...", end="")
    ax_nmf_2d_clustered = fig.add_subplot(2, 4, 6)
    cluster_plot(
        ax_nmf_2d_clustered,
        nmf_2d,
        clustering_method,
        "NMF {clustering_method}".format(clustering_method=clustering_method),
        '2d'
    )
    print("done")

    # 3D projections and clustering

    ax_pca_3d = fig.add_subplot(2, 4, 3, projection='3d')
    ax_pca_3d.set_title("PCA")
    ax_pca_3d.plot(pca_3d[0], pca_3d[1], pca_3d[2], 'o', markeredgecolor='k')

    ax_nmf_3d = fig.add_subplot(2, 4, 4, projection='3d')
    ax_nmf_3d.set_title("NMF")
    ax_nmf_3d.plot(nmf_3d[0], nmf_3d[1], nmf_3d[2], 'o', markeredgecolor='k')

    print("Clustering 3d PCA projection...", end="")
    ax_pca_3d_clustered = fig.add_subplot(2, 4, 7, projection='3d')
    cluster_plot(
        ax_pca_3d_clustered,
        pca_3d,
        clustering_method,
        "PCA {clustering_method}".format(clustering_method=clustering_method),
        '3d'
    )
    print("done")

    print("Clustering 3d NMF projection...", end="")
    ax_nmf_3d_clustered = fig.add_subplot(2, 4, 8, projection='3d')
    cluster_plot(
        ax_nmf_3d_clustered,
        nmf_3d,
        clustering_method,
        "NMF {clustering_method}".format(clustering_method=clustering_method),
        '3d'
    )

    print("done")

    plt.subplots_adjust(left=0.05, bottom=0.05, right=0.95, top=0.95, wspace=0.1, hspace=0.1)
    #fig.tight_layout()

    plt.show()


def vectorize_traces_without_bb(directory):

    def vectorize_trace_without_bb(trace_file):
        seen_sizes = {}
        seen_addresses = {}

        alloc_pattern = '^[mc]alloc\\.\\d+\\((\\d+)\\) = 0x([0-9a-f]+)$'
        failed_alloc_pattern = '^[mc]alloc\\.\\d+\\((\\d+)\\) = \\(nil\\)$'
        free_pattern = '^free\\.\\d+\\(0x([0-9a-f]+)\\)$'

        with open(trace_file, "r") as f:
            lines = f.readlines()

        trace_vector = [0, 0, 0, 0, 0, 0]
        for line in lines:
            # print("line: {line}".format(line=line.rstrip()))
            if line.startswith("malloc"):
                trace_vector[NUM_MALLOCS] += 1

            if line.startswith("calloc"):
                trace_vector[NUM_CALLOCS] += 1

            if line.startswith("malloc") or line.startswith("calloc"):
                match = re.search(alloc_pattern, line)

                if match:
                    size = match.group(1)
                    address = match.group(2)

                    if size not in seen_sizes:
                        seen_sizes[size] = 1

                    if address not in seen_addresses:
                        seen_addresses[address] = 1
                else:
                    match = re.search(failed_alloc_pattern, line)

                    if match:
                        size = match.group(1)

                        if size not in seen_sizes:
                            seen_sizes[size] = 1

                        trace_vector[NUM_FAILED_ALLOCS] += 1

            if line.startswith("free"):
                trace_vector[NUM_FREES] += 1

                match = re.search(free_pattern, line)

                address = match.group(1)

                if address not in seen_addresses:
                    seen_addresses[address] = 1

            # print("vector: [{nm}, {nc}, {nf}, {nus}, {nua}]\n".format(
            #    nm=trace_vector[NUM_MALLOCS],
            #    nc=trace_vector[NUM_CALLOCS],
            #    nf=trace_vector[NUM_FREES],
            #    nus=len(seen_sizes.keys()),
            #    nua=len(seen_addresses.keys())
            # ))

        trace_vector[NUM_UNIQUE_SIZES] = len(seen_sizes.keys())
        trace_vector[NUM_UNIQUE_ADDRS] = len(seen_addresses.keys())

        # print("final vector: [{nm}, {nc}, {nf}, {nus}, {nua}]\n".format(
        #    nm=trace_vector[NUM_MALLOCS],
        #    nc=trace_vector[NUM_CALLOCS],
        #    nf=trace_vector[NUM_FREES],
        #    nus=trace_vector[NUM_UNIQUE_SIZES],
        #    nua=trace_vector[NUM_UNIQUE_ADDRS]
        # ))

        return trace_vector

    trace_vectors = []
    for file in [f for f in os.listdir(directory) if f.endswith(".trace")]:
        trace_vectors.append(vectorize_trace_without_bb("{dir}/{file}".format(
            dir=directory,
            file=file
        )))
    return trace_vectors


def vectorize_traces_with_bb(directory, with_call_order=False):

    def vectorize_trace_with_bb(trace_file, basic_blocks, basic_block_transitions, with_call_order):
        seen_sizes_bb = {}
        seen_addresses_bb = {}

        alloc_pattern = '^[mc]alloc.\\d+\\((\\d+)\\) = 0x([0-9a-f]+)$'
        failed_alloc_pattern = '^[mc]alloc.\\d+\\((\\d+)\\) = \\(nil\\)$'
        free_pattern = '^free.\\d+\\(0x([0-9a-f]+)\\)$'

        trace_vector = [0] * (NUM_FEATURES_PER_BB * len(basic_blocks.keys()))
        if with_call_order:
            trace_vector += ([0] * len(basic_block_transitions.keys()))

        with open(trace_file, "r") as f:
            lines = f.readlines()

        previous_bb = -1
        for line in lines:
            function_call_pattern = "^[a-z]+\\.([0-9]+)"

            match = re.search(function_call_pattern, line)
            current_bb = match.group(1)

            if with_call_order and previous_bb != -1 and current_bb != previous_bb:
                key = "{previous_bb}->{bb}".format(previous_bb=previous_bb, bb=current_bb)
                bb_transition_index = (NUM_FEATURES_PER_BB * len(basic_blocks.keys())) + basic_block_transitions[key]
                trace_vector[bb_transition_index] += 1

            if current_bb not in seen_sizes_bb:
                seen_sizes_bb[current_bb] = {}

            if current_bb not in seen_addresses_bb:
                seen_addresses_bb[current_bb] = {}

            seen_sizes = seen_sizes_bb[current_bb]
            seen_addresses = seen_addresses_bb[current_bb]
            bb_index = basic_blocks[current_bb]

            if line.startswith("malloc") or line.startswith("calloc"):
                failed_alloc = False

                match = re.search(alloc_pattern, line)
                if not match:
                    match = re.search(failed_alloc_pattern, line)
                    if match:
                        failed_alloc = True
                    else:
                        sys.exit("malloc/calloc call didn't match successful or unsuccessful alloc pattern.")

                size = match.group(1)
                address = match.group(2) if not failed_alloc else 0

                if line.startswith("malloc"):
                    trace_vector[(bb_index * NUM_FEATURES_PER_BB) + NUM_MALLOCS] += 1

                if line.startswith("calloc"):
                    trace_vector[(bb_index * NUM_FEATURES_PER_BB) + NUM_CALLOCS] += 1

                if size not in seen_sizes:
                    seen_sizes[size] = 1

                if not failed_alloc:
                    if address not in seen_addresses:
                        seen_addresses[address] = 1
                else:
                    trace_vector[(bb_index * NUM_FEATURES_PER_BB) + NUM_FAILED_ALLOCS] += 1

            if line.startswith("free"):
                trace_vector[(bb_index * NUM_FEATURES_PER_BB) + NUM_FREES] += 1

                match = re.search(free_pattern, line)

                address = match.group(1)

                if address not in seen_addresses:
                    seen_addresses[address] = 1

            for bb in basic_blocks.keys():
                bb_index = basic_blocks[bb]

                if bb in seen_sizes_bb:
                    trace_vector[(bb_index * NUM_FEATURES_PER_BB) + NUM_UNIQUE_SIZES] = len(seen_sizes_bb[bb].keys())

                if bb in seen_addresses_bb:
                    trace_vector[(bb_index * NUM_FEATURES_PER_BB) + NUM_UNIQUE_ADDRS] = len(seen_addresses_bb[bb].keys())

            previous_bb = current_bb

        return trace_vector

    # First we need to identify all basic block numbers based on all the trace files
    trace_files = [
        "{dir}/{file}".format(dir=directory, file=f) for f in os.listdir(directory) if f.endswith(".trace")
    ]

    function_call_pattern = "^[a-z]+\\.([0-9]+)"
    basic_blocks = {}
    basic_block_transitions = {}
    for trace_file in trace_files:
        with open(trace_file, "r") as f:
            lines = f.readlines()

        previous_bb = -1
        for line in lines:
            match = re.search(function_call_pattern, line)
            bb = match.group(1)

            if with_call_order and previous_bb != -1 and bb != previous_bb:
                key = "{previous_bb}->{bb}".format(previous_bb=previous_bb, bb=bb)
                if key not in basic_block_transitions:
                    basic_block_transitions[key] = len(basic_block_transitions.keys())

            if bb not in basic_blocks:
                basic_blocks[bb] = len(basic_blocks.keys())

            previous_bb = bb

    trace_vectors = []
    for trace_file in trace_files:
        trace_vectors.append(vectorize_trace_with_bb(trace_file, basic_blocks, basic_block_transitions, with_call_order))

    return {
        "trace_vectors": trace_vectors,
        "basic_blocks": basic_blocks,
        "basic_block_transitions": basic_block_transitions
    }


def pca(num_components, data):
    return pd.DataFrame(PCA(n_components=num_components).fit_transform(data))


def nmf(num_components, data):
    return pd.DataFrame(NMF(n_components=num_components, max_iter=50000).fit_transform(data))


def cluster_plot(ax, data, clustering_method, title, type='2d'):
    if clustering_method == "dbscan":
        db = DBSCAN(eps=0.1, min_samples=3).fit(data)
        labels = db.labels_
        unique_labels = set(labels)
    elif clustering_method == "optics":
        op = OPTICS(min_samples=3).fit(data)
        labels = op.labels_[op.ordering_]
        unique_labels = set(labels)
    elif clustering_method == "hdbscan":
        hdb = HDBSCAN(min_cluster_size=3)
        labels = hdb.fit_predict(data)
        unique_labels = set(labels)
    else:
        sys.exit("Invalid clustering method")

    ax.set_title("{title} (clusters = {clusters})".format(title=title, clusters=len(unique_labels)))

    #print(Counter(db.labels_))

    cmap = plt.cm.get_cmap("RdYlGn")
    colors = [cmap(each) for each in np.linspace(0, 1, len(unique_labels))]
    for label, color in zip(unique_labels, colors):
        if label == -1:
            color = [0, 0, 0, 1]

        class_member_mask = (labels == label)

        class_data = data[class_member_mask]

        if type == "2d":
            ax.plot(class_data[0], class_data[1], 'o', markerfacecolor=tuple(color), markeredgecolor='k')
        else:
            ax.plot(class_data[0], class_data[1], class_data[2], 'o', markerfacecolor=tuple(color), markeredgecolor='k')


if __name__ == '__main__':
    main()