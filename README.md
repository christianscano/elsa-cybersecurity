## Datasets

**TL;DR: All the datasets can be downloaded [here](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) (registration is required).**

We release a training set composed of 75K applications sampled between 2017-01-01 and 2019-12-31, with 25K applications per year.

For Tracks 1 and 3, we provide two test sets sampled between 2020-01-01 and 2022-06-30, composed of 5000 goodware and 1250 malware applications, respectively.

For Track 3, we provide 4 test sets with applications sampled between 2020-01-01 and 2022-06-30, with 12,5K applications per semester.

![](https://github.com/pralab/elsa-cybersecurity/blob/main/assets/datasets_elsa.png?raw=true)

We sample the datasets from the AndroZoo [1] repository, a growing collection of Android Applications collected from several sources that at the moment contains more than 20 million samples. On the chosen samples, we then collect analysis reports from VirusTotal, from which we extract a timestamp (from the first_submission_date field) and a binary label. A negative label is assigned to those samples that have no detections from the VirusTotal [2] antimalware engines, whereas a positive label is assigned to those samples that are detected by at least 10 antimalware engines. We exclude samples with a number of detections between 1 and 9 in order to discard potentially false positives and grayware applications.

We release the SHA256 hashes of the APK that the participants should consider, in CSV format. They should download the corresponding APKs from the [AndroZoo](https://androzoo.uni.lu/) public repository (after obtaining the API key, which will be granted to everyone affiliated with a university/research institution). The participants must strictly follow the [AndroZoo Access Conditions](https://androzoo.uni.lu/access).

Together with the APK hashes, we provide the application timestamp and (for the training set only) label in the CSV files.

### Pre-computed Features
In addition, for all the released datasets, we also provide the extracted features from the DREBIN [3] feature set in the form of JSON files (one for each APK sample) that are structured as follows:

```
{
  feature_type: [feature1, feature2, …],
  …
}
```

The feature types (and the corresponding feature sets from DREBIN) are:

- features: S1 Hardware components
- req_permissions: S2 Requested permissions
- activities, services, providers, receivers: S3 App components
- intent_filters: S4 Filtered intents
- api_calls: S5 Restricted API calls
- used_permissions: S6 Used permissions
- suspicious_calls: S7 Suspicious API calls
- urls: S8 Network addresses

The pre-computed features can be downloaded [here](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) (registration is required).

## Model implementation instructions
Please, follow these instructions when implementing your detector:
- The model class must necessarily implement the interface defined in the [BaseModel](https://github.com/pralab/android-detectors/blob/main/src/models/base/base_model.py) class. We suggest to extend this class.
- Provide a Python module containing a `load()` method that returns an instance of your trained classifier.
- To ensure reproducibility and allow validating the results, make sure to set all random seeds, add all the requirements, and if necessary a Dockerfile from where to run the evaluation scripts.

In [this repository](https://github.com/pralab/android-detectors) you can find already implemented models which serve as baselines for the benchmarks hosted in the Cybersecurity Use Case.

## Evaluation Instructions

- Create a Python environment and install all the requirements:
```bash
pip install -r track_1/attack_requirements.txt
pip install -r track_2/attack_requirements.txt
pip install -r track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
```

- Read and edit (if needed) the [configuration file](https://github.com/pralab/elsa-cybersecurity/blob/main/config.py).

- Run the `main.py` script passing the path of the Python module loading your detector, the number of the evaluation tracks for which to produce the results and the name of your approach:
```bash
python main.py --clf_loader_path <your_loader_path.py> --track <track number> --method_name <your method name>
```

- Pick the produced file from the `submission` directory and upload it [here](https://benchmarks.elsa-ai.eu/?ch=6&com=mymethods).

If you use Docker, you can run the following commands:
```bash
docker build -t android <your Dockerfile path>
docker run -itd --name android android
docker cp . android:/
docker exec -it android pip install -r /track1/attack_requirements.txt
docker exec -it android pip install -r /track2/attack_requirements.txt
docker exec -it android pip install -r /track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
docker exec -it android python main.py --clf_loader_path <your_loader_path.py> --track <track number> --method_name <your method name>
docker cp android:/submissions/* submissions/
docker stop android
```

### Submission Examples

These commands can be used to produce the submission files for DREBIN classifier.

Download the training dataset, the Track 1 datasets and their pre-extracted features from the [ELSA benchmarks website](https://benchmarks.elsa-ai.eu/?ch=6&com=downloads) inside the `data` directory.

It is recommended to create a new environment. In this example we use conda (it might be required to append `android-detectors/src` directory to the python path before launching the script).
```bash
conda create -n android python=3.9
conda activate android
pip install -r android-detectors/requirements.txt
pip install -r track_1/attack_requirements.txt
pip install -r track_2/attack_requirements.txt
pip install -r track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
export PYTHONPATH="${PYTHONPATH}:android-detectors/src"
python main.py --clf_loader_path android-detectors/src/loaders/drebin_loader.py --track 1 --method_name drebin
python main.py --clf_loader_path android-detectors/src/loaders/drebin_loader.py --track 2 --method_name drebin
python main.py --clf_loader_path android-detectors/src/loaders/drebin_loader.py --track 3 --method_name drebin
```

If you use Docker:
```bash
docker build -t android android-detectors
docker run -itd --name android android
docker cp . android:/
docker exec -it android pip install -r /track_1/attack_requirements.txt
docker exec -it android pip install -r /track_2/attack_requirements.txt
docker exec -it android pip install -r /track_2/problem_space_attack/manipulation/Obfuscapk/src/requirements.txt
docker exec -it android python /main.py --clf_loader_path /android-detectors/src/loaders/drebin_loader.py --track 1 --method_name drebin
docker cp android:/submissions/submission_drebin_track_1.json submissions/
docker exec -it android python /main.py --clf_loader_path /android-detectors/src/loaders/drebin_loader.py --track 2 --method_name drebin
docker cp android:/submissions/submission_drebin_track_2.json submissions/
docker exec -it android python /main.py --clf_loader_path /android-detectors/src/loaders/drebin_loader.py --track 3 --method_name drebin
docker cp android:/submissions/submission_drebin_track_3.json submissions/
docker stop android
```

## Evaluation Metrics
- Detection Rate (a.k.a. True Positive Rate, Track 1 and 2): this metric is computed as the percentage of correctly detected malware and will be used for Track 1 and 2 on a test set containing only malware samples.
- False Positive Rate (Track 1 and 2): this metric is computed as the percentage of legitimate samples wrongly detected as malware and will be used for Track 1 and 2 on a test set containing only legitimate samples.
- F1 Score (Track 3): this metric is computed as the harmonic mean of Precision and Recall, and it is particularly suited for evaluating the binary classification performance on unbalanced datasets in a single metric.
- Area Under Time - AUT (Track 3): this metric was introduced in [4] to evaluate the performance of malware detectors over time. It is based on the trapezoidal rule as the AUC-based metrics. Its value is enclosed in the [0, 1] interval, where an ideal detector with robustness to temporal performance decay has AUT = 1. We compute the metric under point estimates of the F1 Score along the time period of the test samples.

## References

[1] Allix, K., Bissyandé, T.F., Klein, J., & Traon, Y.L. (2016). AndroZoo: Collecting Millions of Android Apps for the Research Community. 2016 IEEE/ACM 13th Working Conference on Mining Software Repositories (MSR), 468-471.

[2] https://www.virustotal.com

[3] Arp, D., Spreitzenbarth, M., Hubner, M., Gascon, H., & Rieck, K. (2014). DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket. Network and Distributed System Security Symposium.

[4] Pendlebury, F., Pierazzi, F., Jordaney, R., Kinder, J., & Cavallaro, L. (2018). TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time. USENIX Security Symposium.