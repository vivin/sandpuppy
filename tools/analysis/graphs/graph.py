import os
import numpy
import pandas
import matplotlib.pyplot as plt
import seaborn
from sklearn import preprocessing
from sklearn.mixture import GaussianMixture, BayesianGaussianMixture
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.decomposition import NMF
from sklearn.cluster import DBSCAN, OPTICS

from hdbscan import HDBSCAN

feature_labels = {
    'num_traces': "Number of Traces",
    'average_counter_segment_length': "Average Counter-Segment Length",
    'average_counter_segment_length_filtered': "Average Counter-Segment Length (filtered)",
    'average_delta': "Average Delta",
    'average_value_set_cardinality_ratio': "Average Value-Set Cardinality Ratio",
    'delta_stddev': "Delta Standard Deviation",
    'lag_one_autocorr': "Lag-One Auto-Correlation",
    'lag_one_autocorr_filtered': "Lag-One Auto-Correlation (filtered)",
    'loop_sequence_proportion': "Loop Sequence Proportion",
    'loop_sequence_proportion_filtered': "Loop Sequence Proportion (filtered)",
    'directional_consistency': "Directional Consistency",
    'max_values_variance': "Maximum Values Variance",
    'max_value_to_input_size_correlation': "Maximum Value to Input-Size Correlation",
    'num_modified_lines': "Number of Modified Lines",
    'num_unique_values': "Number of Unique Values",
    'order_of_magnitudes_stddev': "Order of Magnitudes Standard Deviation",
    'second_difference_roughness': "Second-Difference Roughness",
    'second_difference_roughness_filtered': "Second-Difference Roughness (filtered)",
    'total_counter_segments_filtered_to_num_traces_ratio': "Total Counter Segments (filtered) to Number of Traces Ratio",
    'total_counter_segments_to_num_traces_ratio': "Total Counter Segments to Number of Traces Ratio",
    'times_modified_to_input_size_correlation': "Times Modified to Input-Size Correlation",
    'varying_deltas': "Varying Deltas"
}


def graph_classes(path, variables, classes):
    if len(variables) == 0:
        return

    def cluster_plot(dataset, clustering_method, dimension_reduction_method, graph_type):
        print(
            f"Plotting {graph_type} graph after {dimension_reduction_method} and clustering using {clustering_method}")

        cluster_labels = []
        if clustering_method == "kmeans":
            km = KMeans(n_clusters=len(classes)).fit(dataset)
            cluster_labels = km.labels_
        elif clustering_method == "dbscan":
            db = DBSCAN(eps=0.1, min_samples=2).fit(dataset)
            cluster_labels = db.labels_
        elif clustering_method == "optics":
            op = OPTICS(min_samples=2).fit(dataset)
            cluster_labels = op.labels_[op.ordering_]
        elif clustering_method == "hdbscan":
            hdb = HDBSCAN(min_cluster_size=2)
            cluster_labels = hdb.fit_predict(dataset)
        elif clustering_method == "gmm":
            _gmm = GaussianMixture(n_components=len(classes)).fit(dataset)
            cluster_labels = _gmm.fit_predict(dataset)
        elif clustering_method == "bgmm":
            _bgmm = BayesianGaussianMixture(n_components=len(classes)).fit(dataset)
            cluster_labels = _bgmm.fit_predict(dataset)
        elif clustering_method == "manual":
            cluster_labels = variable_trace_vector_string_labels

        dataset = pandas.concat((dataset, pandas.DataFrame(cluster_labels, columns=['label'])), axis=1)
        if clustering_method == "manual" and dimension_reduction_method == "NMF" and graph_type == "2d":
            with pandas.option_context('display.max_rows', None,
                                       'display.max_columns', None,
                                       'display.max_colwidth', 255,
                                       'display.expand_frame_repr', False):
                print(pandas.concat((dataset, pandas.DataFrame(variable_name_labels, columns=['fqn'])), axis=1))

        grouped_by_label = dataset.groupby('label')

        # Plot vectors after PCA and NMF
        fig = plt.figure(figsize=(20, 10))
        fig.suptitle(f"Clustering method: {clustering_method}")

        if graph_type == "2d":
            ax = fig.add_subplot()
        else:
            ax = fig.add_subplot(projection='3d')

        ax.set_title(dimension_reduction_method)

        for label, group in grouped_by_label:
            if graph_type == "2d":
                ax.plot(group[0], group[1], 'o', label=label)
            else:
                ax.plot(group[0], group[1], group[2], 'o', label=label, markeredgecolor='k')

            ax.legend()
        #        cmap = plt.cm.get_cmap("RdYlGn")
        #        colors = [cmap(each) for each in numpy.linspace(0, 1, len(unique_labels))]
        #        for label, color in zip(unique_labels, colors):
        #            if label == -1:
        #                color = [0, 0, 0, 1]

        #            class_member_mask = (cluster_labels == label)
        #            class_data = dataset[class_member_mask]

        #            if graph_type == "2d":
        #                ax.plot(class_data[0], class_data[1], 'o', markerfacecolor=tuple(color), markeredgecolor='k')
        #                ax.legend()
        #            else:
        #                ax.plot(class_data[0], class_data[1], class_data[2], 'o', markerfacecolor=tuple(color),
        #                        markeredgecolor='k')
        #                ax.legend()

        plt.savefig(f"{clustering_path}/{dimension_reduction_method}_{graph_type}_{clustering_method}.png")
        plt.close(fig)

    def plot_seaborn_group_distributions_for_feature(f_name):
        datasets = [
            labeled_variables,
            kmeans_labeled_variables,
            gmm_labeled_variables,
            # bgmm_labeled_variables
        ]
        clustering_methods = [
            "",
            "_kmeans",
            "_gmm",
            "_bgmm"
        ]
        clustering_methods_labels = [
            "",
            " (k-means clustered)",
            " (Gaussian Mixture Model)",
            " (Bayesian Gaussian Mixture Model)"
        ]
        zipped = zip(datasets, clustering_methods, clustering_methods_labels)
        for dataset, clustering_method, clustering_methods_label in zipped:
            if dataset[f_name].var() > 0:
                displot = seaborn.displot(
                    dataset,
                    x=f_name, col='labels', hue='labels', palette='muted', stat='probability', multiple='dodge'
                )
                displot.fig.suptitle(f"{feature_labels[f_name]}\nHistogram{clustering_methods_label}", y=1.1)
                displot.savefig(f"{histogram_path}/{f_name}_hist_prob{clustering_method}.png")
                plt.close(displot.fig)

                displot = seaborn.displot(
                    dataset,
                    x=f_name, hue='labels', palette='muted', stat='probability', multiple='stack'
                )
                displot.fig.suptitle(f"{feature_labels[f_name]}\nHistogram{clustering_methods_label}", y=1.1)
                displot.savefig(f"{histogram_path}/{f_name}_hist_prob_stack{clustering_method}.png")
                plt.close(displot.fig)

                displot = seaborn.displot(
                    dataset,
                    x=f_name, col='labels', hue='labels', palette='muted', stat='density', common_norm=False,
                    multiple='dodge'
                )
                displot.fig.suptitle(
                    f"{feature_labels[f_name]}\nCategory-normalized Histogram{clustering_methods_label}", y=1.1
                )
                displot.savefig(f"{histogram_path}/{f_name}_hist_class_norm{clustering_method}.png")
                plt.close(displot.fig)

                displot = seaborn.displot(
                    dataset,
                    x=f_name, hue='labels', palette='muted', stat='density', common_norm=False, multiple='stack'
                )
                displot.fig.suptitle(
                    f"{feature_labels[f_name]}\nCategory-normalized Histogram{clustering_methods_label}", y=1.1
                )
                displot.savefig(f"{histogram_path}/{f_name}_hist_class_norm_stack{clustering_method}.png")
                plt.close(displot.fig)

                displot = seaborn.displot(
                    dataset,
                    x=f_name, hue='labels', palette='muted', kind='kde', bw_adjust=0.25, fill=True
                )
                displot.fig.suptitle(f"{feature_labels[f_name]}\nKernel density estimate{clustering_methods_label}", y=1.1)
                displot.savefig(f"{histogram_path}/{f_name}_hist_kde{clustering_method}.png")
                plt.close(displot.fig)

                dataset['Constant'] = "Data"

                stripplot = seaborn.stripplot(
                    x=dataset['Constant'], y=dataset[f_name], hue=dataset['labels'], palette='muted', jitter=True
                )
                stripplot.figure.suptitle(f"{feature_labels[f_name]}\nStrip Plot{clustering_methods_label}")
                stripplot.figure.savefig(f"{strip_plot_path}/{f_name}_strip_plot{clustering_method}.png")
                plt.close(stripplot.figure)

                plt.figure(figsize=(32, 16))
                swarmplot = seaborn.swarmplot(
                    x=dataset['Constant'], y=dataset[f_name], hue=dataset['labels'], palette='muted'
                )
                swarmplot.figure.suptitle(f"{feature_labels[f_name]}\nSwarm Plot{clustering_methods_label}")
                swarmplot.figure.savefig(f"{swarm_plot_path}/{f_name}_swarm_plot{clustering_method}.png")
                plt.close(swarmplot.figure)

    def plot_seaborn_bivariate_distributions_for_features(f1_name, f2_name):
        datasets = [
            labeled_variables,
            kmeans_labeled_variables,
            gmm_labeled_variables,
            # bgmm_labeled_variables
        ]
        clustering_methods = [
            "",
            "_kmeans",
            "_gmm",
            "_bgmm"
        ]
        clustering_methods_labels = [
            "",
            " (k-means clustered)",
            " (Gaussian Mixture Model)",
            " (Bayesian Gaussian Mixture Model)"
        ]
        zipped = zip(datasets, clustering_methods, clustering_methods_labels)
        for dataset, clustering_method, clustering_methods_label in zipped:
            if dataset[f1_name].var() > 0 and dataset[f2_name].var() > 0:
                displot = seaborn.displot(
                    dataset,
                    x=f1_name, y=f2_name, hue='labels', palette='deep'
                )
                displot.fig.suptitle(
                    f"{feature_labels[f1_name]} vs {feature_labels[f2_name]}\nHeatmap{clustering_methods_label}",
                    y=1.1
                )
                displot.savefig(f"{bivariate_path}/{f1_name}_vs_{f2_name}_heatmap{clustering_method}.png")
                plt.close(displot.fig)

                try:
                    jointplot = seaborn.jointplot(
                        data=dataset,
                        x=f1_name, y=f2_name, hue='labels', palette='deep'
                    )
                    jointplot.fig.suptitle(
                        f"{feature_labels[f1_name]} vs {feature_labels[f2_name]}\nScatter plot{clustering_methods_label}",
                        y=1.1
                    )
                    jointplot.savefig(f"{bivariate_path}/{f1_name}_vs_{f2_name}_scatterplot{clustering_method}.png")
                    plt.close(jointplot.fig)
                except numpy.linalg.LinAlgError:
                    print("Not plotting because of singular matrix")

                # try:
                #     jointplot = seaborn.jointplot(
                #         data=dataset,
                #         x=f1_name, y=f2_name, hue='labels', palette='deep', kind="kde", bw_adjust=0.25, fill=True
                #     )
                #     jointplot.fig.suptitle(
                #         f"{feature_labels[f1_name]} vs {feature_labels[f2_name]}\nContour map{clustering_methods_label}",
                #         y=1.1
                #     )
                #     jointplot.savefig(f"{bivariate_path}/{f1_name}_vs_{f2_name}_contour{clustering_method}.png")
                #     plt.close(jointplot.fig)
                # except numpy.linalg.LinAlgError:
                #     print("Not plotting because of singular matrix")

    histogram_path = f"{path}/histograms"
    if not os.path.isdir(histogram_path):
        os.makedirs(histogram_path)

    bivariate_path = f"{path}/bivariate"
    if not os.path.isdir(bivariate_path):
        os.makedirs(bivariate_path)

    clustering_path = f"{path}/clustering"
    if not os.path.isdir(clustering_path):
        os.makedirs(clustering_path)

    strip_plot_path = f"{path}/strip_plot"
    if not os.path.isdir(strip_plot_path):
        os.makedirs(strip_plot_path)

    swarm_plot_path = f"{path}/swarm_plot"
    if not os.path.isdir(swarm_plot_path):
        os.makedirs(swarm_plot_path)

    # Filter out only those variables belonging to the classes we want to graph
    variables_to_graph = [variable for variable in variables if variable['class'] in classes]

    # Every requested class may not actually be present, so let us actually figure out which classes are present by
    # counting how many variables are present in each provided class.
    class_counts = {clazz: 0 for clazz in classes}
    for variable in variables_to_graph:
        class_counts[variable['class']] += 1

    # Only use those classes that have at least one variable
    classes_present = []
    for clazz in class_counts.keys():
        if class_counts[clazz] > 0:
            classes_present.append(clazz)

    print(f"Requested classes: {classes}")
    print(f"Classes present: {classes_present}\n")

    classes = classes_present

    # Map string class labels and integer class labels to each other.
    integer_class_label = 0
    string_class_label_to_integer = {}
    for variable_class in classes:
        string_class_label_to_integer[variable_class] = integer_class_label
        integer_class_label += 1

    # This will hold the data we will use for graphing
    data = {feature_name: [] for feature_name in feature_labels.keys()}
    data['varying_deltas'] = []
    data['type'] = []

    variable_trace_vector_integer_labels = []
    variable_trace_vector_string_labels = []
    variable_name_labels = []

    for variable_to_graph in variables_to_graph:
        features = variable_to_graph['features']

        for feature_name in feature_labels.keys():
            data[feature_name].append(features[feature_name])

        data['varying_deltas'][-1] = 1 if features['varying_deltas'] else 0
        data['type'].append(variable_to_graph['class'])
        variable_trace_vector_string_labels.append(variable_to_graph['class'])
        variable_trace_vector_integer_labels.append(string_class_label_to_integer[variable_to_graph['class']])
        variable_name_labels.append(variable_to_graph['fqn'])

    df = pandas.DataFrame(data)

    # TODO: to do better classification, try to think what the features mean. for example, if you have an enum from
    # TODO: input that has average value set cardinality ratio 1, then sure it might be an enum, but it might be the
    # TODO: kind of variable that keeps track of required elements on input structure. for example, a file format may
    # TODO: need to have a certain number of sections (in any particular order, or in perhaps in the SAME order [how do
    # TODO: we identify these? we can ignore these types I think -- basically see if a variable has the exact same trace
    # TODO: each time]) to be a valid file. so those numbers that represent these sections will show up every time. so
    # TODO: it is an enum, but not necessarily one we need to instrument. so we could classify these differently maybe?
    # TODO: or even ignore them??

    selected_feature_names = [
#        'average_delta',
        'average_value_set_cardinality_ratio',
#        'delta_stddev',
#        'lag_one_autocorr',
        'loop_sequence_proportion',
        'directional_consistency',
        'max_values_variance',
        'max_value_to_input_size_correlation',
        'num_modified_lines',
        'num_unique_values',
#        'order_of_magnitudes_stddev',
        'times_modified_to_input_size_correlation',
#        'varying_deltas'
    ]
    selected_features = df.filter(selected_feature_names)

    # When you write the paper, i think you can say that it makes sense to cap max_values_variance make it
    # categorical or binary as 0,1. because logically it makes sense based on the semantics. it's not something we need
    # to use clustering to figure out.
    #selected_features.loc[selected_features.average_delta < 255, 'average_delta'] = 0
    #selected_features.loc[selected_features.average_delta > 1000, 'average_delta'] = 1000
    #selected_features.loc[selected_features.delta_stddev < 255, 'delta_stddev'] = 0
    #selected_features.loc[selected_features.delta_stddev > 1000, 'delta_stddev'] = 1000
    #selected_features.loc[selected_features.order_of_magnitudes_stddev < 1, 'order_of_magnitudes_stddev'] = 0
    #selected_features.loc[selected_features.order_of_magnitudes_stddev > 1, 'order_of_magnitudes_stddev'] = 1
    #selected_features.loc[selected_features.num_unique_values < 255, 'num_unique_values'] = 0
    #selected_features.loc[selected_features.num_unique_values > 255, 'num_unique_values'] = 1
    selected_features.loc[selected_features.max_values_variance > 0, 'max_values_variance'] = 1

    #print(clustering_features.describe())
    #print("")

    scaler = preprocessing.MinMaxScaler()
    selected_features_normalized = scaler.fit_transform(selected_features)

    print("Performing PCA (2 and 3 dimensions)")
    pca_2d = pandas.DataFrame(PCA(n_components=2).fit_transform(selected_features_normalized))
    pca_3d = pandas.DataFrame(PCA(n_components=3).fit_transform(selected_features_normalized))

    print("Performing NMF (2 and 3 dimensions)")
    nmf_2d = pandas.DataFrame(NMF(n_components=2, max_iter=75000).fit_transform(selected_features_normalized))
    nmf_3d = pandas.DataFrame(NMF(n_components=3, max_iter=75000).fit_transform(selected_features_normalized))

    for clustering_method in ["kmeans", "gmm", "manual"]: #, "bgmm"
        cluster_plot(pca_2d, clustering_method, "PCA", "2d")
        cluster_plot(pca_3d, clustering_method, "PCA", "3d")
        cluster_plot(nmf_2d, clustering_method, "NMF", "2d")
        cluster_plot(nmf_3d, clustering_method, "NMF", "3d")

    print("Clustering variables using k-means and {num} clusters".format(num=len(classes)))
    kmeans = KMeans(n_clusters=len(classes)).fit(selected_features_normalized)
    kmeans_labels = pandas.DataFrame(kmeans.labels_)
    kmeans_labeled_variables = pandas.concat((selected_features, kmeans_labels), axis=1)
    kmeans_labeled_variables = kmeans_labeled_variables.rename({0: 'labels'}, axis=1)

    print("Clustering variables using Gaussian Mixture Model and {num} clusters".format(num=len(classes)))
    gmm = GaussianMixture(n_components=len(classes)).fit(selected_features_normalized)
    gmm_labels = pandas.DataFrame(gmm.fit_predict(selected_features_normalized))
    gmm_labeled_variables = pandas.concat((selected_features, gmm_labels), axis=1)
    gmm_labeled_variables = gmm_labeled_variables.rename({0: 'labels'}, axis=1)

    #print("Clustering variables using Bayesian Gaussian Mixture Model and {num} clusters".format(num=len(classes)))
    #bgmm = BayesianGaussianMixture(n_components=len(classes), max_iter=1000, tol=1e-4).fit(clustering_features_normalized)
    #bgmm_labels = pandas.DataFrame(bgmm.fit_predict(clustering_features_normalized))
    #bgmm_labeled_variables = pandas.concat((clustering_features, bgmm_labels), axis=1)
    #bgmm_labeled_variables = bgmm_labeled_variables.rename({0: 'labels'}, axis=1)

    labels = pandas.DataFrame(variable_trace_vector_string_labels)
    labeled_variables = pandas.concat((selected_features, labels), axis=1)
    labeled_variables = labeled_variables.rename({0: 'labels'}, axis=1)

    for i in range(0, len(selected_feature_names)):
        independent_feature = selected_feature_names[i]

        print("Plotting group histograms, strip plots, and swarm plots for {x}...".format(x=feature_labels[independent_feature]))
        plot_seaborn_group_distributions_for_feature(independent_feature)

        for j in range(i + 1, len(selected_feature_names)):
            dependent_feature = selected_feature_names[j]

            print("Plotting various distribution visualizations of {y} with respect to {x}...".format(
                y=feature_labels[dependent_feature],
                x=feature_labels[independent_feature]
            ))
            plot_seaborn_bivariate_distributions_for_features(independent_feature, dependent_feature)

        print("")
