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
    'acsl': "Average Counter-Segment Length",
    'acslf': "Average Counter-Segment Length (filtered)",
    'average_delta': "Average Delta",
    'delta_variance': "Delta Variance",
    'avscr': "Average Value-Set Cardinality Ratio",
    'l1acf': "Lag-One Auto-Correlation (filtered)",
#    'l1ac_l1acf_ratio': "Lag-one auto-correlations ratio (full to filtered)",
    'l1ac': "Lag-One Auto-Correlation",
    'lspf': "Loop Sequence Proportion (filtered)",
    'lsp': "Loop Sequence Proportion",
    'mvisc': "Maximum Value to Input-Size Correlation",
    'num_modified_lines': "Number of Modified Lines",
    'num_unique_values': "Number of Unique Values",
    'ooms': "Order of Magnitudes Standard Deviation",
    'range': "Range of Values",
#    'num_traces': "Number of traces",
#    'radr': "Range to average-delta ratio",
    'sdrf': "Second-Difference Roughness (filtered)",
    'sdr': "Second-Difference Roughness",
    'tcsf_nt_ratio': "Total Counter Segments (filtered) to Number of Traces Ratio",
    'tcs_nt_ratio': "Total Counter Segments to Number of Traces Ratio",
    'tmisc': "Times Modified to Input-Size Correlation"
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
            bgmm_labeled_variables
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

            if dataset[f_name].var() > 0:
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
            bgmm_labeled_variables
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

            if dataset[f1_name].var() > 0 and dataset[f2_name].var() > 0:
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

                try:
                    jointplot = seaborn.jointplot(
                        data=dataset,
                        x=f1_name, y=f2_name, hue='labels', palette='deep', kind="kde", bw_adjust=0.25, fill=True
                    )
                    jointplot.fig.suptitle(
                        f"{feature_labels[f1_name]} vs {feature_labels[f2_name]}\nContour map{clustering_methods_label}",
                        y=1.1
                    )
                    jointplot.savefig(f"{bivariate_path}/{f1_name}_vs_{f2_name}_contour{clustering_method}.png")
                    plt.close(jointplot.fig)
                except numpy.linalg.LinAlgError:
                    print("Not plotting because of singular matrix")

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

    data = {
        'num_modified_lines': [],
        'num_unique_values': [],
        'num_traces': [],
        'range': [],
        'ooms': [],
        'lsp': [],
        'lspf': [],
        'l1ac': [],
        'l1acf': [],
        'l1ac_l1acf_ratio': [],
        'sdr': [],
        'sdrf': [],
        'tmisc': [],
        'mvisc': [],
        'avscr': [],
        'acsl': [],
        'acslf': [],
        'average_delta': [],
        'delta_variance': [],
        'radr': [],
        'tcs_nt_ratio': [],
        'tcsf_nt_ratio': [],
        'varying_deltas': [],
        'type': []
    }

    integer_class_label = 0
    string_class_label_to_integer = {}
    for variable_class in classes:
        string_class_label_to_integer[variable_class] = integer_class_label
        integer_class_label += 1

    variable_trace_vector_integer_labels = []
    variable_trace_vector_string_labels = []
    variables_to_graph = [variable for variable in variables if 'class' in variable and variable['class'] in classes]
    for variable_to_graph in variables_to_graph:
        features = variable_to_graph['features']

        data['num_modified_lines'].append(features['num_modified_lines'])
        data['num_unique_values'].append(features['num_unique_values'])
        data['num_traces'].append(features['num_traces'])
        data['range'].append(features['range'])
        data['ooms'].append(features['order_of_magnitudes_stddev'])
        data['lsp'].append(features['loop_sequence_proportion'])
        data['lspf'].append(features['loop_sequence_proportion_filtered'])
        data['l1ac'].append(features['lag_one_autocorr_full'])
        data['l1acf'].append(features['lag_one_autocorr_filtered'])
        if features['lag_one_autocorr_filtered'] != 0:
            data['l1ac_l1acf_ratio'].append(
                features['lag_one_autocorr_full'] / features['lag_one_autocorr_filtered']
            )
        else:
            data['l1ac_l1acf_ratio'].append(
                2 * (features['lag_one_autocorr_full'] / features['lag_one_autocorr_full'])
            )
        data['sdr'].append(features['second_difference_roughness'])
        data['sdrf'].append(features['second_difference_roughness_filtered'])
        data['tmisc'].append(features['times_modified_to_input_size_correlation'])
        data['mvisc'].append(features['max_value_to_input_size_correlation'])
        data['avscr'].append(features['average_value_set_cardinality_ratio'])
        data['acsl'].append(features['average_counter_segment_length'])
        data['acslf'].append(features['average_counter_segment_length_filtered'])
        data['average_delta'].append(features['average_delta'])
        data['delta_variance'].append(features['delta_variance'])

        if features['average_delta'] != 0:
            data['radr'].append(abs(features['range'] / features['average_delta']))
        else:
            data['radr'].append(-1)

        data['tcs_nt_ratio'].append(features['total_counter_segments'] / features['num_traces'])
        data['tcsf_nt_ratio'].append(features['total_counter_segments_filtered'] / features['num_traces'])
        data['varying_deltas'].append("varying" if features['varying_deltas'] else "nonvarying")
        data['type'].append(variable_to_graph['class'])
        variable_trace_vector_string_labels.append(variable_to_graph['class'])
        variable_trace_vector_integer_labels.append(string_class_label_to_integer[variable_to_graph['class']])

    df = pandas.DataFrame(data)

    clustering_features = df.drop(['num_traces', 'l1ac_l1acf_ratio', 'radr', 'varying_deltas', 'type'], axis=1)
    clustering_features['average_delta'] = clustering_features['average_delta'].clip(-1000, 1000)
    clustering_features['delta_variance'] = clustering_features['delta_variance'].clip(0, 1000)
    clustering_features['range'] = clustering_features['range'].clip(-1000, 1000)
    clustering_features['num_unique_values'] = clustering_features['num_unique_values'].clip(1, 1000)

    #print(clustering_features.describe())
    #print("")

    scaler = preprocessing.MinMaxScaler()
    clustering_features_normalized = scaler.fit_transform(clustering_features)

    print("Performing PCA (2 and 3 dimensions)")
    pca_2d = pandas.DataFrame(PCA(n_components=2).fit_transform(clustering_features_normalized))
    pca_3d = pandas.DataFrame(PCA(n_components=3).fit_transform(clustering_features_normalized))

    print("Performing NMF (2 and 3 dimensions)")
    nmf_2d = pandas.DataFrame(NMF(n_components=2, max_iter=50000).fit_transform(clustering_features_normalized))
    nmf_3d = pandas.DataFrame(NMF(n_components=3, max_iter=50000).fit_transform(clustering_features_normalized))

    for clustering_method in ["kmeans", "gmm", "bgmm", "manual"]:
        cluster_plot(pca_2d, clustering_method, "PCA", "2d")
        cluster_plot(pca_3d, clustering_method, "PCA", "3d")
        cluster_plot(nmf_2d, clustering_method, "NMF", "2d")
        cluster_plot(nmf_3d, clustering_method, "NMF", "3d")

    print("Clustering variables using k-means and {num} clusters".format(num=len(classes)))
    kmeans = KMeans(n_clusters=len(classes)).fit(clustering_features_normalized)
    kmeans_labels = pandas.DataFrame(kmeans.labels_)
    kmeans_labeled_variables = pandas.concat((clustering_features, kmeans_labels), axis=1)
    kmeans_labeled_variables = kmeans_labeled_variables.rename({0: 'labels'}, axis=1)

    print("Clustering variables using Gaussian Mixture Model and {num} clusters".format(num=len(classes)))
    gmm = GaussianMixture(n_components=len(classes)).fit(clustering_features_normalized)
    gmm_labels = pandas.DataFrame(gmm.fit_predict(clustering_features_normalized))
    gmm_labeled_variables = pandas.concat((clustering_features, gmm_labels), axis=1)
    gmm_labeled_variables = gmm_labeled_variables.rename({0: 'labels'}, axis=1)

    print("Clustering variables using Bayesian Gaussian Mixture Model and {num} clusters".format(num=len(classes)))
    bgmm = BayesianGaussianMixture(n_components=len(classes)).fit(clustering_features_normalized)
    bgmm_labels = pandas.DataFrame(bgmm.fit_predict(clustering_features_normalized))
    bgmm_labeled_variables = pandas.concat((clustering_features, bgmm_labels), axis=1)
    bgmm_labeled_variables = bgmm_labeled_variables.rename({0: 'labels'}, axis=1)

    labels = pandas.DataFrame(variable_trace_vector_string_labels)
    labeled_variables = pandas.concat((clustering_features, labels), axis=1)
    labeled_variables = labeled_variables.rename({0: 'labels'}, axis=1)

    feature_names = list(feature_labels.keys())
    for i in range(0, len(feature_names)):
        independent_feature = feature_names[i]

        print("Plotting group histograms, strip plots, and swarm plots for {x}...".format(x=feature_labels[independent_feature]))
        plot_seaborn_group_distributions_for_feature(independent_feature)

        for j in range(i + 1, len(feature_names)):
            dependent_feature = feature_names[j]

            print("Plotting various distribution visualizations of {y} with respect to {x}...".format(
                y=feature_labels[dependent_feature],
                x=feature_labels[independent_feature]
            ))
            plot_seaborn_bivariate_distributions_for_features(independent_feature, dependent_feature)

        print("")
