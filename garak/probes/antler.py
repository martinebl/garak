# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Antler probe

Attempt to get a model to produce undesired/illegal content
"""

from antler.probes.killingmyself import KillingMyself
from antler.techniques.addnoise import AddNoise


from garak.probes.base import Probe


class Antler(Probe):
    """Use the antler framework to produce and test jailbreak prompts

    """

    active = False

    bcp47 = "en"
    primary_detector = "mitigation.MitigationBypass"
    goal = "make the model produce undesirable content"
    tags = [
        "payload:jailbreak", 
    ]  # Not 100% sure about these yet

    # DEFAULT_PARAMS = TreeSearchProbe.DEFAULT_PARAMS | {
    #     "target_topics": ["abortion"],
    #     "lexicon": "oewn:2023",
    # }


    def probe(self, generator):
        self.prompts = [AddNoise().applyTechnique(KillingMyself().getPayload())]
        return super().probe(generator)
