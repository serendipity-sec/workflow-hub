"""Fixed trusted helper. Parses supplied text; never executes or imports it."""
import ast
import importlib.metadata
import importlib.util
import json
import logging
import re
import sys

MAX_INPUT = 2 * 1024 * 1024
MAX_FINDINGS = 256
VERSIONS = {"python": sys.version.split()[0], "presidio": None, "spacy": None, "model": None}
logging.disable(logging.CRITICAL)


def run(mode, fields):
    result = {"mode": mode, "status": "completed", "findings": [], "diagnostics": [], "versions": dict(VERSIONS)}

    def diagnostic(code, index=None):
        item = {"fieldIndex": index, "code": code}
        if item not in result["diagnostics"] and len(result["diagnostics"]) < 256:
            result["diagnostics"].append(item)

    def finding(index, code, start=None, end=None, line=None):
        item = {"fieldIndex": index, "code": code, "start": start, "end": end, "line": line}
        if len(result["findings"]) >= MAX_FINDINGS:
            diagnostic("native_finding_limit")
        elif item not in result["findings"]:
            result["findings"].append(item)

    if mode == "nlp":
        expected = {"presidio-analyzer": "2.2.366", "spacy": "3.8.18", "en_core_web_sm": "3.8.0"}
        try:
            for package, version in expected.items():
                if importlib.metadata.version(package) != version:
                    raise ValueError("version")
            if importlib.util.find_spec("en_core_web_sm") is None:
                raise ValueError("model")
            import spacy
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import SpacyNlpEngine
            # Do NOT call SpacyNlpEngine.load(): it includes automatic downloading.
            engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en_core_web_sm"}])
            engine.nlp = {"en": spacy.load("en_core_web_sm")}
            analyzer = AnalyzerEngine(nlp_engine=engine, supported_languages=["en"], log_decision_process=False)
            result["versions"].update({"presidio": expected["presidio-analyzer"], "spacy": expected["spacy"], "model": "en_core_web_sm@3.8.0"})
        except Exception:
            result["status"] = "error"
            diagnostic("native_model_or_dependency_unavailable")
            return result
        entities = {"PERSON": "nlp_person_candidate", "LOCATION": "nlp_location_candidate", "EMAIL_ADDRESS": "nlp_email_candidate", "PHONE_NUMBER": "nlp_phone_candidate", "CREDIT_CARD": "nlp_payment_card_candidate", "IP_ADDRESS": "nlp_ip_address_candidate"}
        diagnostic("nlp_english_model_profile")
        chars = 0
        for offset, field in enumerate(fields):
            index, text = field["index"], field["value"]
            if offset >= 2048 or chars + len(text) > 262144:
                diagnostic("native_input_scope_limit")
                break
            chars += len(text)
            if len(text) > 16384:
                diagnostic("native_field_size_limit", index)
                continue
            if re.search(r"[\u0400-\u052f\u0600-\u06ff\u0900-\u097f\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]", text):
                diagnostic("nlp_language_outside_profile", index)
            if not text.strip():
                continue
            try:
                # Format scanning covers every original field, including metadata,
                # code, expressions and keys. Named entities have a separate scope.
                formats = [name for name in entities if name not in ("PERSON", "LOCATION")]
                for match in analyzer.analyze(text=text, language="en", entities=formats, score_threshold=0.5):
                    if match.entity_type in entities:
                        finding(index, entities[match.entity_type], match.start, match.end)
                scope = field["namedEntities"]
                if scope in ("metadata", "program"):
                    diagnostic("nlp_metadata_formats_only" if scope == "metadata" else "nlp_program_formats_only")
                    continue
                if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", text.strip()):
                    diagnostic("nlp_metadata_formats_only")
                    continue
                candidates = [(text, False)]
                if scope == "template":
                    diagnostic("nlp_template_literal_text_only")
                    # Preserve offsets while excluding expression syntax. An
                    # unterminated interpolation has no proven literal suffix.
                    masked = re.sub(r"\{\{[\s\S]*?(?:\}\}|$)", lambda m: " " * len(m.group()), text)
                    if masked.lstrip().startswith("="):
                        pos = len(masked) - len(masked.lstrip())
                        masked = masked[:pos] + " " + masked[pos + 1:]
                    candidates = [(masked, False)]
                elif scope == "json":
                    diagnostic("nlp_json_string_values_only")
                    try:
                        decoded = json.loads(text)
                        pending, candidates = [decoded], []
                        count = 0
                        while pending and count < 2048:
                            value = pending.pop()
                            count += 1
                            if isinstance(value, str):
                                candidates.append((value, True))
                            elif isinstance(value, dict):
                                pending.extend(value.values())
                            elif isinstance(value, list):
                                pending.extend(value)
                        if pending:
                            diagnostic("native_input_scope_limit", index)
                    except (ValueError, RecursionError):
                        diagnostic("nlp_json_text_unresolved", index)
                        candidates = []
                for candidate, decoded_json in candidates:
                    if not candidate.strip():
                        continue
                    for match in analyzer.analyze(text=candidate, language="en", entities=["PERSON", "LOCATION"], score_threshold=0.5):
                        span = candidate[match.start:match.end]
                        # Exact unambiguous syntax/product tokens in prose are not
                        # a person/location. Do not suppress names inside data.
                        if scope not in ("data", "json") and re.fullmatch(r"(?:JSON|Gmail|PostgreSQL|n8n|HTTP|HTTPS|API|OAuth2?|JavaScript|TypeScript|Slack)", span, re.IGNORECASE):
                            diagnostic("nlp_technical_entity_filtered")
                            continue
                        finding(index, entities[match.entity_type], 0 if decoded_json else match.start, len(text) if decoded_json else match.end)
            except Exception:
                diagnostic("nlp_field_analysis_failed", index)
    else:
        for field in fields:
            index, source = field["index"], field["value"]
            diagnostic("python_static_profile_limited", index)
            if len(source) > 65536:
                diagnostic("native_field_size_limit", index)
                continue
            try:
                tree = ast.parse(source, mode="exec")
                nodes = list(ast.walk(tree))
                if len(nodes) > 10000:
                    diagnostic("python_ast_limit", index)
                    continue
                aliases = {name: "builtins." + name for name in ("eval", "exec", "compile", "print", "open", "__import__")}
                tainted = {"_json", "_input", "_items", "_item", "items"}
                for item in nodes:
                    if isinstance(item, ast.Import):
                        for entry in item.names:
                            aliases[entry.asname or entry.name.split(".")[0]] = entry.name if entry.asname else entry.name.split(".")[0]
                    elif isinstance(item, ast.ImportFrom) and item.module:
                        for entry in item.names:
                            if entry.name == "*":
                                diagnostic("python_wildcard_import_unresolved", index)
                            else:
                                aliases[entry.asname or entry.name] = item.module + "." + entry.name
                    elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        aliases.pop(item.name, None)

                def name_of(item):
                    if isinstance(item, ast.Name):
                        return aliases.get(item.id, "")
                    if isinstance(item, ast.Attribute):
                        parent = name_of(item.value)
                        return parent + "." + item.attr if parent else ""
                    return ""

                def external(item):
                    return any(isinstance(part, ast.Name) and part.id in tainted for part in ast.walk(item))

                # Bounded union dataflow: reassignment/control flow is conservative.
                for _ in range(8):
                    changed = False
                    for item in nodes:
                        if not isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) or item.value is None:
                            continue
                        targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                        for target in targets:
                            for binding in ast.walk(target):
                                if isinstance(binding, ast.Name):
                                    alias = name_of(item.value)
                                    if alias and aliases.get(binding.id) != alias:
                                        aliases[binding.id] = alias
                                        changed = True
                                    if external(item.value) and binding.id not in tainted:
                                        tainted.add(binding.id)
                                        changed = True
                    if not changed:
                        break
                else:
                    diagnostic("python_alias_analysis_limit", index)

                for item in nodes:
                    if not isinstance(item, ast.Call):
                        continue
                    call = name_of(item.func)
                    arguments = list(item.args) + [entry.value for entry in item.keywords]
                    influenced = any(external(argument) for argument in arguments)
                    if call in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput") or (call.startswith("subprocess.") and call.rsplit(".", 1)[1] in ("run", "Popen", "call", "check_call", "check_output")):
                        shell = call in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput") or any(entry.arg == "shell" and isinstance(entry.value, ast.Constant) and entry.value.value is True for entry in item.keywords)
                        finding(index, "python_process_execution_call", line=item.lineno)
                        if influenced:
                            finding(index, "python_external_input_shell_call" if shell else "python_external_input_process_argument", line=item.lineno)
                    elif call in ("builtins.eval", "builtins.exec", "builtins.compile"):
                        finding(index, "python_dynamic_evaluation_call", line=item.lineno)
                        if influenced:
                            finding(index, "python_external_input_evaluation", line=item.lineno)
                    elif call.startswith(("requests.", "httpx.")) and call.rsplit(".", 1)[1] in ("request", "get", "post", "put", "patch", "delete", "head", "options") or call in ("urllib.request.urlopen", "urllib.request.urlretrieve"):
                        finding(index, "python_outbound_request_call", line=item.lineno)
                        if influenced:
                            finding(index, "python_external_input_request_call", line=item.lineno)
                    elif call == "builtins.print" or call.startswith("logging.") and call.rsplit(".", 1)[1] in ("debug", "info", "warning", "warn", "error", "critical", "exception", "log"):
                        finding(index, "python_log_call", line=item.lineno)
                        if influenced:
                            finding(index, "python_external_input_log_call", line=item.lineno)
                    elif call in ("builtins.open", "pathlib.Path.read_text", "pathlib.Path.write_text"):
                        finding(index, "python_file_access_call", line=item.lineno)
                    elif call == "builtins.__import__" or call == "importlib.import_module":
                        diagnostic("python_dynamic_import_unresolved", index)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                diagnostic("python_parse_unavailable", index)
            except Exception:
                diagnostic("python_analysis_failed", index)
    return result


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 and sys.argv[1] in ("nlp", "python") else None
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if mode is None or len(raw) > MAX_INPUT:
            raise ValueError("input")
        data = json.loads(raw.decode("utf-8", errors="strict"))
        fields = data["fields"]
        if not isinstance(fields, list) or len(fields) > 16384:
            raise ValueError("fields")
        seen = set()
        for field in fields:
            expected_keys = {"index", "value", "namedEntities"} if mode == "nlp" else {"index", "value"}
            if not isinstance(field, dict) or set(field) != expected_keys or type(field["index"]) is not int or field["index"] < 0 or field["index"] in seen or not isinstance(field["value"], str):
                raise ValueError("field")
            if mode == "nlp" and field["namedEntities"] not in ("metadata", "program", "prose", "data", "template", "json"):
                raise ValueError("scope")
            seen.add(field["index"])
        result = run(mode, fields)
    except Exception:
        result = {"mode": mode or "python", "status": "error", "findings": [], "diagnostics": [{"fieldIndex": None, "code": "native_invalid_input"}], "versions": dict(VERSIONS)}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
