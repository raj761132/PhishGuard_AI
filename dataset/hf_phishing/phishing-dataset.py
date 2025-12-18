# Copyright 2020 The HuggingFace Datasets Authors and the current dataset script contributor.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# TODO: Address all TODOs and remove all explanatory comments
"""TODO: Add a description here."""


import csv
import json
import os

import datasets


# TODO: Add BibTeX citation
# Find for instance the citation on arxiv or on the dataset repo/website
_CITATION = """\
@InProceedings{ealvaradob:dataset,
title = {Phishing Datasets},
author={Esteban Alvarado},
year={2024}
}
"""

_DESCRIPTION = """\
Dataset designed for phishing classification tasks in various data types.
"""
_HOMEPAGE = ""

_LICENSE = ""

_URLS = {
    "texts": "texts.json",
    "urls": "urls.json",
    "webs": "webs.json",
    "combined_full": "combined_full.json",
    "combined_reduced": "combined_reduced.json"
}


class PhishingDatasets(datasets.GeneratorBasedBuilder):
    """Phishing Datasets Configuration"""

    VERSION = datasets.Version("1.1.0")

    BUILDER_CONFIGS = [
        datasets.BuilderConfig(name="texts", version=VERSION, description="text subset"),
        datasets.BuilderConfig(name="urls", version=VERSION, description="urls subset"),
        datasets.BuilderConfig(name="webs", version=VERSION, description="webs subset"),
        datasets.BuilderConfig(name="combined_full", version=VERSION, description="combined dataset that have all URLs"),
        datasets.BuilderConfig(name="combined_reduced", version=VERSION, description="combined dataset that doesn't have all URLs for representativity issues"),
    ]

    DEFAULT_CONFIG_NAME = "combined_reduced"

    def _info(self):
        features = datasets.Features(
            {
                "text": datasets.Value("string"),
                "label": datasets.Value("int64"),
            }
        )
        return datasets.DatasetInfo(
            description=_DESCRIPTION,
            features=features,
            supervised_keys=("text", "label"),
            homepage=_HOMEPAGE,
            license=_LICENSE,
            citation=_CITATION,
        )

    def _split_generators(self, dl_manager):
        urls = _URLS[self.config.name]
        data_dir = dl_manager.download_and_extract(urls)
        return [
            datasets.SplitGenerator(
                name=datasets.Split.TRAIN,
                gen_kwargs={
                    "filepath": data_dir,
                    "split": "train",
                },
            ),
        ]

    def _generate_examples(self, filepath, split):
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
            for index, sample in enumerate(data):
                yield index, {
                    "text": sample['text'],
                    "label": sample['label']
                }