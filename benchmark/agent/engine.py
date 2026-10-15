"""Single local EA, original author VA matcher/DA, explicit model-task adaptation.

No labels, sample IDs, endpoint IDs, file paths, or model catalog from ICSLibrary
are accepted by inference methods. Only a banner derived from input is accepted.
"""
import dataclasses
import hashlib
import json
import math
import sys
import time
from pathlib import Path
import os
ROOT = Path(__file__).resolve().parent
from rules import present

# Upstream modules are installed into a user-specified runtime directory by run.py.


def clean_json(value):
    if isinstance(value, dict):
        return {k: clean_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_json(v) for v in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def banner_from_input(evidence):
    assert isinstance(evidence, dict) and set(evidence) == {'protocol', 'responses'}
    text = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    for forbidden in ['sample_id', 'endpoint_id', 'model_label', 'true_label', 'anonymized_ip', 'agent_original_path']:
        assert f'"{forbidden}"' not in text
    return text


class LocalEA:
    def __init__(self, config):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel
        self.torch = torch
        self.config = config
        torch.set_num_threads(4)
        torch.manual_seed(config['seed'])
        if not torch.cuda.is_available():
            raise RuntimeError('CUDA unavailable; no implicit model/device replacement')
        free, total = torch.cuda.mem_get_info()
        if free < 6 * 1024**3:
            raise RuntimeError(f'GPU busy or insufficient free memory: {free} bytes')
        base = Path(config['base_model'])
        adapter = Path(config['adapter'])
        self.tokenizer = AutoTokenizer.from_pretrained(adapter, local_files_only=True)
        if config['prompt_format'] == 'chat' and not self.tokenizer.chat_template:
            base_tokenizer = AutoTokenizer.from_pretrained(base, local_files_only=True)
            assert base_tokenizer.get_vocab() == self.tokenizer.get_vocab(), 'Base/adapter tokenizer mismatch'
            if not base_tokenizer.chat_template:
                raise RuntimeError('Official base tokenizer has no chat template')
            self.tokenizer.chat_template = base_tokenizer.chat_template
        quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4',
            bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16)
        started = time.monotonic()
        model = AutoModelForCausalLM.from_pretrained(base, local_files_only=True,
            quantization_config=quant, device_map={'': 0}, torch_dtype=torch.float16,
            attn_implementation='sdpa')
        self.model = PeftModel.from_pretrained(model, adapter, local_files_only=True,
            is_trainable=False, autocast_adapter_dtype=False).eval()
        for name, parameter in self.model.named_parameters():
            if 'lora_' in name:
                parameter.data = parameter.data.to(torch.float16)
        self.resource = {'load_seconds': time.monotonic() - started,
            'gpu_name': torch.cuda.get_device_name(0), 'free_before_bytes': free,
            'total_bytes': total, 'allocated_after_load': torch.cuda.memory_allocated(),
            'lora_dtypes': sorted({str(p.dtype) for n, p in self.model.named_parameters() if 'lora_' in n}),
            'torch_version': torch.__version__}
        print(json.dumps({'model_loaded': self.resource}), flush=True)

    def generate(self, prompt):
        from transformers import LogitsProcessor, LogitsProcessorList, StoppingCriteria, StoppingCriteriaList
        torch, tokenizer = self.torch, self.tokenizer
        tokens = []

        class Capture(LogitsProcessor):
            def __call__(self, input_ids, scores):
                token_id = int(scores[0].argmax())
                logprob = float(torch.log_softmax(scores[0].float(), dim=-1)[token_id])
                tokens.append({'token_id': token_id, 'logprob': logprob,
                    'decoded_token': tokenizer.decode([token_id], skip_special_tokens=False, clean_up_tokenization_spaces=False)})
                return scores

        class EndResults(StoppingCriteria):
            def __call__(self, input_ids, scores, **kwargs):
                tail = tokenizer.decode(input_ids[0, -16:], skip_special_tokens=False)
                return '</results>' in tail.lower() or '\n\n\n\n' in tail

        if self.config['prompt_format'] == 'chat':
            prompt = tokenizer.apply_chat_template([{'role': 'user', 'content': prompt}], tokenize=False, add_generation_prompt=True)
        encoded = tokenizer(prompt, return_tensors='pt', add_special_tokens=False).to('cuda')
        input_tokens = encoded['input_ids'].shape[1]
        if input_tokens + self.config['max_new_tokens'] > self.config['context_limit']:
            raise ValueError(f'Input exceeds frozen context limit: {input_tokens} tokens; no silent truncation')
        torch.cuda.reset_peak_memory_stats()
        started = time.monotonic()
        with torch.inference_mode():
            generated = self.model.generate(**encoded, max_new_tokens=self.config['max_new_tokens'],
                do_sample=False, temperature=None, top_p=None, top_k=None, repetition_penalty=1.0,
                logits_processor=LogitsProcessorList([Capture()]),
                stopping_criteria=StoppingCriteriaList([EndResults()]),
                pad_token_id=tokenizer.eos_token_id, use_cache=True)
        output_ids = generated[0, input_tokens:]
        assert len(tokens) == len(output_ids)
        assert [x['token_id'] for x in tokens] == output_ids.tolist()
        raw = tokenizer.decode(output_ids, skip_special_tokens=True, clean_up_tokenization_spaces=False)
        # Author's analyzer aligns token character spans; use identical per-token reconstruction.
        reconstructed = ''.join(x['decoded_token'] for x in tokens)
        if reconstructed.replace(tokenizer.eos_token or '', '').rstrip() != raw.rstrip():
            # Byte-level Unicode may require merged decoding; refuse silently misaligned DA features.
            raise ValueError('Token text alignment differs; inspect development fixture before continuing')
        return {'raw': reconstructed, 'logprobs': tokens, 'prompt_text': prompt, 'input_tokens': input_tokens,
            'output_tokens': len(tokens), 'seconds': time.monotonic() - started,
            'peak_allocated_bytes': torch.cuda.max_memory_allocated(),
            'peak_reserved_bytes': torch.cuda.max_memory_reserved(),
            'hit_generation_limit': len(tokens) >= self.config['max_new_tokens']}


class ModelTaskPipeline:
    def __init__(self, config, load_ea=True):
        from Knowledge_graph_construct.result_verify import TripletValidator
        from discriminator_construct.analysis_token_logprobs import AttributeConfidenceAnalyzer
        from discriminator_construct.confidence_discriminator import ConfidenceDiscriminator
        self.config = config
        source = Path(config['author_source'])
        brand = json.loads((source / 'KB-device_database/firmware_database_all_brand_1118.json').read_text())
        model = json.loads((source / 'KB-device_database/firmware_database_all_model_1118.json').read_text())
        self.validator = TripletValidator(brand, model)
        self.analyzer = AttributeConfidenceAnalyzer()
        self.discriminator = ConfidenceDiscriminator.load(str(source / 'discriminator_construct/discriminator_model_optimized_xgb_1204.pkl'))
        if 'model' not in self.discriminator.models:
            raise RuntimeError('Author DA model attribute missing; fallback acceptance forbidden')
        expected = set(self.discriminator.feature_names)
        if expected != set(self.discriminator._get_empty_features()):
            raise RuntimeError('Author DA feature schema differs from shipped classifier')
        self.first_prompt = (ROOT / 'config/first_pass.txt').read_text()
        self.second_prompt = (ROOT / 'config/second_pass.txt').read_text()
        self.ea = LocalEA(config) if load_ea else None
        self._validation_cache = {}

    def extraction(self, prompt):
        output = self.ea.generate(prompt)
        parsed = self.analyzer.extract_json_result(output['raw'])
        if output['hit_generation_limit'] or not isinstance(parsed, dict) or not isinstance(parsed.get('model'), dict):
            raise ValueError(f'EA incomplete or invalid structured output; incomplete generation')
        for attr in ['brand', 'model', 'firmware_version']:
            if not isinstance(parsed.get(attr), dict):
                raise ValueError(f'Missing required output field {attr}; incomplete generation')
            value = parsed[attr].get('value')
            if value is not None and not isinstance(value, str):
                raise ValueError(f'Invalid value type for {attr}; incomplete generation')
        analysis = self.analyzer.analyze_full_output(output['raw'], output['logprobs'])
        if present(parsed['model']['value']) and not analysis['model']['token_count']:
            raise ValueError(f'No model reasoning token logprobs; incomplete generation')
        return {'parsed': parsed, 'analysis': clean_json(analysis),
            'resource': {k: v for k, v in output.items() if k not in {'raw', 'logprobs', 'prompt_text'}}}

    def first(self, banner):
        return self.extraction(self.first_prompt.replace('{{BANNER}}', banner))

    def validate_model(self, parsed):
        brand = parsed['brand']['value'] if present(parsed['brand']['value']) else ''
        model = parsed['model']['value'] if present(parsed['model']['value']) else ''
        if not model:
            return []
        key = (brand, model)
        if key in self._validation_cache:
            return self._validation_cache[key]
        # Use author's hierarchical model matches. Firmware omitted from acceptance.
        _, model_matches, _ = self.validator.validate_triplets([brand] if brand else [], [model], [],
            confidence_threshold=self.config['va_threshold'], max_model_results=5)
        matches = []
        for items in model_matches.values():
            for m in items:
                row = {k: v for k, v in dataclasses.asdict(m).items() if k != 'version_list'}
                if row not in matches:
                    matches.append(row)
        self._validation_cache[key] = sorted(matches, key=lambda m: -m['confidence'])[:5]
        return self._validation_cache[key]

    def full(self, banner, first):
        matches = self.validate_model(first['parsed'])
        if matches and matches[0]['confidence'] > self.config['va_threshold']:
            return {'pred_model': first['parsed']['model']['value'], 'accepted': True,
                'reason': 'first_pass_kb_model_verified', 'va_matches': matches, 'second_pass': None, 'da': None}
        context = json.dumps([{'brand': m['brand'], 'model': m['matched']} for m in matches], ensure_ascii=False)
        prompt = self.second_prompt.replace('{{BANNER}}', banner).replace('{{KNOWN_MODEL_LIST}}', context)
        prompt = prompt.replace('{{FIRST_EXTRACTION_JSON}}', json.dumps(first['parsed'], ensure_ascii=False))
        second = self.extraction(prompt)
        second_matches = self.validate_model(second['parsed'])
        value = second['parsed']['model']['value']
        if second_matches and second_matches[0]['confidence'] > self.config['va_threshold']:
            accepted, reason, da = present(value), 'second_pass_kb_model_verified', None
        else:
            # Preserve author model-specific threshold; no brand/firmware conjunction.
            da = self.discriminator.predict(second['analysis'], 'model')
            # Original final decision also requires mean attribute confidence > 0.5.
            # With only model evaluated, that mean is the model's confidence itself.
            accepted = present(value) and da['decision'] == 'ACCEPT' and da['confidence_score'] > self.config['da_final_floor']
            da['final_model_confidence_floor'] = self.config['da_final_floor']
            reason = 'model_da_accept' if accepted else 'model_da_reject_or_null'
        return {'pred_model': value if accepted else None, 'candidate_model': value,
            'accepted': accepted, 'reason': reason, 'va_matches': matches,
            'second_va_matches': second_matches, 'second_pass': second, 'da': da}
