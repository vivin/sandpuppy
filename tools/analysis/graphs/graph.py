import pandas
import matplotlib.pyplot as plt
import seaborn

from collections.abc import Iterable


def graph_classes(path, variables, classes):

    def plot_group_scatterplots_for_features(f1_name, f2_name, x_label, y_label, filename):
        for label, group in grouped_by_type:
            plt.plot(group[f1_name], group[f2_name], marker='o', linestyle='', markersize=4, label=label, alpha=0.5)

        plt.plot(vd_group[f1_name], vd_group[f2_name], marker='*', linestyle='', markersize=3, label="varying", alpha=0.5)

        plt.xlabel(x_label)
        plt.ylabel(y_label)
        plt.legend(bbox_to_anchor=(1.05, 1))

        plt.savefig(filename, bbox_inches='tight', dpi=200)
        plt.close()

    def plot_group_histograms_for_feature(f_name, bins, hist_range, x_label, filename):
        num_plots = len(grouped_by_type.groups.keys())
        fig, axs = plt.subplots(nrows=num_plots, ncols=1)
        fig.suptitle(x_label)

        # If there is only one group of variables we are going to plot axs ends up being a single object and not an
        # iterable containing a single object. Since the loop below expects it to be an iterable, we are going to
        # change axs into a list containing itself.
        if num_plots == 1:
            axs = [axs]

        lines = []
        labels = []
        for (label, group), ax, color in zip(grouped_by_type, axs, seaborn.color_palette()):
            ax.hist(group[f_name], bins=bins, range=hist_range, label=label, color=color, alpha=0.5)
            ax_line, ax_label = ax.get_legend_handles_labels()
            lines += ax_line
            labels += ax_label

        fig.legend(lines, labels, bbox_to_anchor=(0.925, 0.5), loc='center left')
        fig.subplots_adjust(hspace=.75)

        plt.savefig(filename, bbox_inches='tight', dpi=200)
        plt.close()

    data = {
        'lsp': [],
        'lspf': [],
        'l1ac': [],
        'l1acf': [],
        'sdr': [],
        'sdrf': [],
        'tmisc': [],
        'mvisc': [],
        'avscr': [],
        'acsl': [],
        'acslf': [],
        'average_delta': [],
        'varying_deltas': [],
        'type': []
    }

    variables_to_graph = [variable for variable in variables if 'class' in variable and variable['class'] in classes]
    for variable_to_graph in variables_to_graph:
        variable_features = variable_to_graph['features']
        data['lsp'].append(variable_features['loop_sequence_proportion'])
        data['lspf'].append(variable_features['loop_sequence_proportion_filtered'])
        data['l1ac'].append(variable_features['lag_one_autocorr_full'])
        data['l1acf'].append(variable_features['lag_one_autocorr_filtered'])
        data['sdr'].append(variable_features['second_difference_roughness'])
        data['sdrf'].append(variable_features['second_difference_roughness_filtered'])
        data['tmisc'].append(variable_features['times_modified_to_input_size_correlation'])
        data['mvisc'].append(variable_features['max_value_to_input_size_correlation'])
        data['avscr'].append(variable_features['average_value_set_cardinality_ratio'])
        data['acsl'].append(variable_features['average_counter_segment_length'])
        data['acslf'].append(variable_features['average_counter_segment_length_filtered'])
        data['average_delta'].append(variable_features['average_delta'])
        data['varying_deltas'].append("varying" if variable_features['varying_deltas'] else "nonvarying")
        data['type'].append(variable_to_graph['class'])

    df = pandas.DataFrame(data)
    grouped_by_type = df.groupby('type')
    vd_group = df.groupby('varying_deltas').get_group('varying')

    plot_group_scatterplots_for_features(
        'lsp',
        'l1acf',
        "Loop sequence proportion",
        "Lag-one auto-correlation (filtered)",
        f"{path}/lsp_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'lspf',
        'l1acf',
        "Loop sequence proportion (filtered)",
        "Lag-one auto-correlation (filtered)",
        f"{path}/lspf_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'tmisc',
        'l1acf',
        "Times modified to input-size correlation",
        "Lag-one auto-correlation (filtered)",
        f"{path}/tmisc_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'avscr',
        'l1ac',
        "Average value set cardinality ratio",
        "Lag-one auto-correlation",
        f"{path}/avscr_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'avscr',
        'l1acf',
        "Average value set cardinality ratio",
        "Lag-one auto-correlation (filtered)",
        f"{path}/avscr_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'avscr',
        'lsp',
        "Average value set cardinality ratio",
        "Loop sequence proportion",
        f"{path}/avscr_average_delta.png"
    )
    plot_group_scatterplots_for_features(
        'avscr',
        'lspf',
        "Average value set cardinality ratio",
        "Loop sequence proportion (filtered)",
        f"{path}/avscr_average_delta.png"
    )

    plot_group_histograms_for_feature(
        'lsp',
        100,
        (df['lsp'].min(), df['lsp'].max()),
        "Loop sequence proportion",
        f"{path}/lsp_hist.png"
    )
    plot_group_histograms_for_feature(
        'lspf',
        100,
        (df['lspf'].min(), df['lspf'].max()),
        "Loop sequence proportion (filtered)",
        f"{path}/lspf_hist.png"
    )
    plot_group_histograms_for_feature(
        'l1ac',
        100,
        (df['l1ac'].min(), df['l1ac'].max()),
        "Lag-one autocorrelation",
        f"{path}/l1ac_hist.png"
    )
    plot_group_histograms_for_feature(
        'l1acf',
        100,
        (df['l1acf'].min(), df['l1acf'].max()),
        "Lag-one autocorrelation (filtered)",
        f"{path}/l1acf_hist.png"
    )
    plot_group_histograms_for_feature(
        'tmisc',
        100,
        (df['tmisc'].min(), df['tmisc'].max()),
        "Times-modified and input-size correlation",
        f"{path}/tmisc_hist.png"
    )
    plot_group_histograms_for_feature(
        'mvisc',
        100,
        (df['mvisc'].min(), df['mvisc'].max()),
        "Maximum-value and input-size correlation",
        f"{path}/mvisc_hist.png"
    )
    plot_group_histograms_for_feature(
        'avscr',
        100,
        (df['avscr'].min(), df['avscr'].max()),
        "Average value-set cardinality ratio",
        f"{path}/avscr_hist.png"
    )
    plot_group_histograms_for_feature(
        'average_delta',
        100,
        (df['average_delta'].min(), df['average_delta'].max()),
        "Average delta",
        f"{path}/average_delta_hist.png"
    )
    plot_group_histograms_for_feature(
        'acsl',
        100,
        (df['acsl'].min(), df['acsl'].max()),
        "Average counter-segment length",
        f"{path}/acsl_hist.png"
    )
    plot_group_histograms_for_feature(
        'acslf',
        100,
        (df['acslf'].min(), df['acslf'].max()),
        "Average counter-segment length (filtered)",
        f"{path}/acslf_hist.png"
    )
    plot_group_histograms_for_feature(
        'sdr',
        100,
        (df['sdr'].min(), df['sdr'].max()),
        "Second-difference roughness",
        f"{path}/sdr_hist.png"
    )
    plot_group_histograms_for_feature(
        'sdrf',
        100,
        (df['sdrf'].min(), df['sdr'].max()),
        "Second-difference roughness (filtered)",
        f"{path}/sdrf_hist.png"
    )
