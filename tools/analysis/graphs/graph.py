import pandas
import matplotlib.pyplot as plt
import seaborn


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
        fig, axs = plt.subplots(nrows=len(grouped_by_type.groups.keys()), ncols=1)
        fig.suptitle(x_label)

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
        'l1acf': [],
        'tmisc': [],
        'avscr': [],
        'average_delta': [],
        'varying_deltas': [],
        'type': []
    }

    variables_to_graph = [variable for variable in variables if 'class' in variable and variable['class'] in classes]
    for variable_to_graph in variables_to_graph:
        variable_features = variable_to_graph['features']
        data['lsp'].append(variable_features['loop_sequence_proportion'])
        data['lspf'].append(variable_features['loop_sequence_proportion_filtered'])
        data['l1acf'].append(variable_features['lag_one_autocorr_filtered'])
        data['tmisc'].append(variable_features['times_modified_to_input_size_correlation'])
        data['varying_deltas'].append("varying" if variable_features['varying_deltas'] else "nonvarying")
        data['type'].append(variable_to_graph['class'])
        data['avscr'].append(variable_features['average_value_set_cardinality_ratio'])
        data['average_delta'].append(variable_features['average_delta'])

    df = pandas.DataFrame(data)
    grouped_by_type = df.groupby('type')
    vd_group = df.groupby('varying_deltas').get_group('varying')

    plot_group_scatterplots_for_features(
        'lsp',
        'l1acf',
        "Loop sequence proportion",
        "Lag-one auto-correlation (filtered)",
        f"{path}/all_counters_enums_lsp_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'lspf',
        'l1acf',
        "Loop sequence proportion (filtered)",
        "Lag-one auto-correlation (filtered)",
        f"{path}/all_counters_enums_lspf_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'tmisc',
        'l1acf',
        "Times modified to input-size correlation",
        "Lag-one auto-correlation (filtered)",
        f"{path}/all_counters_enums_tmisc_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'avscr',
        'l1acf',
        "Average value set cardinality ratio",
        "Lag-one auto-correlation (filtered)",
        f"{path}/all_counters_enums_avscr_l1acf.png"
    )
    plot_group_scatterplots_for_features(
        'avscr',
        'average_delta',
        "Average value set cardinality ratio",
        "Average delta",
        f"{path}/all_counters_enums_avscr_average_delta.png"
    )

    plot_group_histograms_for_feature(
        'lsp',
        100,
        (0, 1),
        "Loop sequence proportion",
        f"{path}/lsp_hist.png"
    )
    plot_group_histograms_for_feature(
        'lspf',
        100,
        (0, 1),
        "Loop sequence proportion (filtered)",
        f"{path}/lspf_hist.png"
    )
    plot_group_histograms_for_feature(
        'l1acf',
        200,
        (-1, 1),
        "Lag-one autocorrelation (filtered)",
        f"{path}/l1acf_hist.png"
    )
    plot_group_histograms_for_feature(
        'tmisc',
        100,
        (0, 1),
        "Times-modified and input-size correlation",
        f"{path}/tmisc_hist.png"
    )
    plot_group_histograms_for_feature(
        'avscr',
        100,
        (0, 1),
        "Average value-set cardinality ratio",
        f"{path}/avscr_hist.png"
    )
    plot_group_histograms_for_feature(
        'average_delta',
        100,
        (df['average_delta'].min(), df['average_delta'].max()),
        'Average delta',
        f"{path}/average_delta_hist.png"
    )
