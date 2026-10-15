"""
Fingerprint extraction algorithms for the CLI workflow.
"""

import numpy as np
from tqdm import tqdm

from .lcs import advanced_approximate_match


def obtain_fingerprint_from_large_file(
    all_data, label_data_list, is_large, max_repeat, match_variation_allowed,
    refinement_support=0.6
):
    """Extract fingerprint from large traffic files with volume-based filtering."""
    def split_data(merged_data, split_gap):
        groups = []
        s_data = []
        for data in merged_data:
            if len(s_data) == 0:
                s_data.append(data)
                continue
            if data[0] - s_data[-1][0] > split_gap:
                groups.append(s_data)
                s_data = []
            s_data.append(data)
        groups.append(s_data)
        return groups

    average_packet_num = len(all_data) / max_repeat
    print("Average packet number:", average_packet_num)

    if is_large:
        filtered_data = traffic_filtering(all_data)
    else:
        filtered_data = all_data

    print("Is large volume:", is_large)
    print("Splitting data into groups")
    grouped_data = split_data(filtered_data, split_gap=15.0)
    print(f"Splitting data into {len(grouped_data)} groups")

    potential_fingerprints = _extract_potential_fingerprints(
        grouped_data, label_data_list, large_volume=is_large
    )

    refined_fingerprints = []
    for i in tqdm(range(len(potential_fingerprints)), desc="Extracting potential fingerprints"):
        fingerprint = potential_fingerprints[i]
        fingerprint, _ = _advanced_refinement(
            grouped_data, label_data_list, fingerprint, max_repeat, is_large,
            refinement_support=refinement_support
        )
        if len(fingerprint) == 0:
            continue
        refined_fingerprints.append(fingerprint)

    print("Refined fingerprints:", [len(fp) for fp in refined_fingerprints])
    fingerprint = _merge_fingerprint(refined_fingerprints)
    print("Before final refinement:", fingerprint)

    matched_idx_counter = []
    for i in tqdm(range(5)):
        fingerprint, matched_idx_counter = _advanced_refinement(
            grouped_data, label_data_list, fingerprint, max_repeat,
            large_volume=is_large, variation_threshold=match_variation_allowed,
            refinement_support=refinement_support
        )
        print(len(matched_idx_counter), len(fingerprint))
        if len(fingerprint) == len(matched_idx_counter):
            print("Refinement finished")
            break

    print("Matched index counter", matched_idx_counter)
    print("After final refinement:", fingerprint)
    return fingerprint


def _extract_potential_fingerprints(packet_seq_by_cluster, label_data_list, large_volume=False):
    """Extract potential fingerprints from grouped data."""
    potential_fingerprints = []
    for i in tqdm(range(len(packet_seq_by_cluster)), desc="Cross event matching"):
        for j in range(i+1, len(packet_seq_by_cluster)):
            seq1 = packet_seq_by_cluster[i].copy()
            seq2 = packet_seq_by_cluster[j].copy()
            seq1.insert(0, (label_data_list[i], 0, 'UP'))
            seq2.insert(0, (label_data_list[j], 0, 'UP'))

            if not large_volume:
                min_dist, min_indices = advanced_approximate_match(seq1, seq2)
                if min_dist > 2 or len(min_indices) < 3:
                    continue
                potential_fp = [seq1[index_pair[0]] for index_pair in min_indices]
                potential_fingerprints.append(potential_fp)
            else:
                fp_segments, seg_times = _period_segmentation(seq1)
                candidate_segments, _ = _period_segmentation(seq2, seg_times)
                potential_fp = []
                for j in range(len(fp_segments)):
                    fp = fp_segments[j]
                    candidate = candidate_segments[j]
                    min_dist, min_indices = advanced_approximate_match(candidate, fp)
                    if min_dist < 1 and len(min_indices) >= 2:
                        for index_pair in min_indices:
                            if index_pair == (0, 0):
                                continue
                            potential_fp.append(fp[index_pair[1]])
                potential_fp.insert(0, seq1[0])
                potential_fingerprints.append(potential_fp)

    return potential_fingerprints


def _merge_fingerprint(potential_fingerprints):
    """Merge multiple potential fingerprints into one."""
    fingerprint = []
    for i in range(len(potential_fingerprints)):
        cur_fp = potential_fingerprints[i]
        if len(fingerprint) == 0:
            fingerprint = [list(pkt) for pkt in cur_fp]
            continue
        min_dist, min_indices = advanced_approximate_match(fingerprint, cur_fp)
        fingerprint_first_match = fingerprint[min_indices[0][0]][0]
        cur_fp_first_match = cur_fp[min_indices[0][1]][0]
        matched_indices = [index_pair[1] for index_pair in min_indices]
        for pkt in fingerprint:
            pkt[0] -= fingerprint_first_match
        for i in range(len(cur_fp)):
            if i not in matched_indices:
                pkt = list(cur_fp[i])
                pkt[0] -= cur_fp_first_match
                if tuple(pkt) not in fingerprint:
                    fingerprint.append(pkt)
        fingerprint = sorted(fingerprint, key=lambda x: x[0])

    fingerprint_set = set([tuple(pkt) for pkt in fingerprint])
    fingerprint = [list(pkt) for pkt in fingerprint_set]
    fingerprint = sorted(fingerprint, key=lambda x: x[0])
    return fingerprint


def _advanced_refinement(
    grouped_data, label_data_list, fingerprint, max_repeat,
    large_volume=False, variation_threshold=0.5, refinement_support=0.6
):
    """Advanced refinement with large volume support."""
    def _obtain_candidates(packet, packets, time_threshold=5.0):
        packet_time, _, packet_direction = packet
        candidates = [packet]
        for p in packets:
            if p[0] <= packet_time + time_threshold:
                candidates.append(p)
        return candidates

    matched_indices_counter = [0] * len(fingerprint)
    for i in range(len(grouped_data)):
        if len(fingerprint) == 0:
            break
        data = grouped_data[i]
        candidates = _obtain_candidates(
            data[0], data[1:],
            fingerprint[-1][0] - fingerprint[0][0] + 2
        )
        candidates.insert(0, (label_data_list[i], 0, 'UP'))

        if not large_volume:
            min_dist, min_indices = advanced_approximate_match(
                candidates, fingerprint, variation_thresh=variation_threshold
            )
            if min_dist < 1 and len(min_indices) >= 2:
                for index_pair in min_indices:
                    matched_indices_counter[index_pair[1]] += 1
            continue

        fp_segments, seg_times = _period_segmentation(fingerprint)
        candidate_segments, _ = _period_segmentation(candidates, seg_times)
        acc_idx = 0
        for j in range(len(fp_segments)):
            fp = fp_segments[j]
            candidate = candidate_segments[j]
            min_dist, min_indices = advanced_approximate_match(
                candidate, fp, variation_thresh=variation_threshold
            )
            if min_dist < 1 and len(min_indices) >= 2:
                for index_pair in min_indices:
                    if index_pair == (0, 0):
                        continue
                    matched_indices_counter[acc_idx + index_pair[1]] += 1
            acc_idx += len(fp) - 1
        matched_indices_counter[0] += 1

    final_fingerprint = []
    for i in range(len(fingerprint)):
        if matched_indices_counter[i] >= max_repeat * refinement_support:
            final_fingerprint.append(fingerprint[i])

    return final_fingerprint, matched_indices_counter


def traffic_filtering(all_data):
    """Filter traffic for large volume data."""
    print("Before filtering:", len(all_data))
    filtered_data = _filter_frequent_packets(all_data)
    print("After filtering:", len(filtered_data))
    merged_data = _compress_consecutive_data(filtered_data)
    print("After Compression:", len(merged_data))
    return merged_data


def _filter_frequent_packets(all_data, sigma=2):
    """Filter frequently occurring packets using Z-score."""
    frequency = {"UP": {}, "DOWN": {}}
    for packet in all_data:
        if packet[1] not in frequency[packet[2]]:
            frequency[packet[2]][packet[1]] = 0
        frequency[packet[2]][packet[1]] += 1

    frequency["UP"] = dict(sorted(frequency["UP"].items(), key=lambda x: x[1], reverse=True))
    frequency["DOWN"] = dict(sorted(frequency["DOWN"].items(), key=lambda x: x[1], reverse=True))

    up_sizes = list(frequency["UP"].keys())
    up_values = np.array(list(frequency["UP"].values()))
    down_sizes = list(frequency["DOWN"].keys())
    down_values = np.array(list(frequency["DOWN"].values()))

    z_score_up = (up_values - np.mean(up_values)) / np.std(up_values)
    z_score_down = (down_values - np.mean(down_values)) / np.std(down_values)

    filtered_sizes = {"UP": [], "DOWN": []}
    for i in range(len(z_score_up)):
        if abs(z_score_up[i]) >= sigma:
            filtered_sizes["UP"].append(up_sizes[i])
    for i in range(len(z_score_down)):
        if abs(z_score_down[i]) >= sigma:
            filtered_sizes["DOWN"].append(down_sizes[i])

    print("Filtered sizes:", filtered_sizes)

    filtered_data = []
    for data in all_data:
        if data[2] == "UP" and data[1] in filtered_sizes["UP"]:
            continue
        if data[2] == "DOWN" and data[1] in filtered_sizes["DOWN"]:
            continue
        filtered_data.append(data)

    return filtered_data


def _compress_consecutive_data(all_data):
    """Compress consecutive packets with same size and direction."""
    merged_data = []
    cur_merge_target = None
    for data in all_data:
        if cur_merge_target is None:
            cur_merge_target = data
        else:
            if (data[1] == cur_merge_target[1] and
                data[2] == cur_merge_target[2] and
                abs(data[0] - cur_merge_target[0]) < 1):
                continue
            else:
                merged_data.append(cur_merge_target)
                cur_merge_target = data
    merged_data.append(cur_merge_target)
    return merged_data


def _period_segmentation(sequence, sep_times=None):
    """Segment sequence by time periods."""
    fp_times = np.array([pkt[0] for pkt in sequence])
    start_time = fp_times[0]

    if sep_times is None:
        time_diffs = np.diff(fp_times)
        sep_times = []
        for i, diff in enumerate(time_diffs):
            if i == 0:
                continue
            if diff >= 0.2:
                sep_times.append((fp_times[i+1] + fp_times[i]) / 2)
        if len(sep_times) == 0:
            gap = (fp_times[-1] - fp_times[1]) / 3
            sep_times = np.arange(fp_times[1] + gap, fp_times[-1], gap)
        sep_times = list(np.array(sep_times) - start_time)

    sep_fps = []
    sliding_seq_idx = 1
    for cur_sep_time in sep_times:
        cur_sep_seq = [sequence[0]]
        for i in range(sliding_seq_idx, len(fp_times)):
            if sequence[i][0] < cur_sep_time + start_time:
                cur_sep_seq.append(sequence[i])
            else:
                break
        sliding_seq_idx = i
        sep_fps.append(cur_sep_seq)

    for i in range(sliding_seq_idx, len(fp_times)):
        cur_sep_seq = [sequence[0]]
        for i in range(sliding_seq_idx, len(fp_times)):
            cur_sep_seq.append(sequence[i])
    sep_fps.append(cur_sep_seq)

    return sep_fps, sep_times
