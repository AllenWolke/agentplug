"""显式联网准备固定commit；运行Provider不联网或加载远程代码。"""
from pathlib import Path
import argparse
import hashlib
import json
from engine import ModelSpec


def main():
    from huggingface_hub import snapshot_download
    parser=argparse.ArgumentParser()
    parser.add_argument("--model",required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--lock",type=Path,default=Path(__file__).with_name("models.lock.json"))
    args=parser.parse_args()
    spec=ModelSpec.load(args.lock,args.model)
    directory=args.output/spec.id
    patterns=["config.json","tokenizer.json","tokenizer_config.json","special_tokens_map.json",
                        "sentencepiece.bpe.model","*.safetensors","model.safetensors.index.json",
                        "vocab.txt","added_tokens.json","README.md"]
    if spec.id=='bge-m3':patterns.append('pytorch_model.bin')
    snapshot_download(spec.repository,revision=spec.revision,local_dir=directory,
                      allow_patterns=patterns,max_workers=2)
    if not any(path.suffix=='.safetensors' or path.name=='pytorch_model.bin' for path in directory.iterdir()):
        raise ValueError('model weight preparation incomplete')
    files=[]
    for path in sorted(directory.iterdir()):
        if not path.is_file():continue
        digest=hashlib.sha256()
        with path.open('rb') as source:
            for block in iter(lambda:source.read(1<<20),b''):digest.update(block)
        files.append({'path':path.name,'bytes':path.stat().st_size,'sha256':digest.hexdigest()})
    manifest={'version':'model-asset-manifest/v1','repository':spec.repository,'revision':spec.revision,'files':files}
    (directory/'asset-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'model':spec.id,'revision':spec.revision,'files':len(files),'bytes':sum(row['bytes'] for row in files)}))


if __name__=='__main__':main()
