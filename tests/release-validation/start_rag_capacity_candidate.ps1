$ErrorActionPreference='Stop'
$name='lexagent-rag-capacity-candidate'
if(docker ps -a --filter "name=^/$name$" --format '{{.Names}}'){throw 'candidate exists; inspect before replacing'}
$source=(docker inspect lexagent-release-verify-rag-server-1|ConvertFrom-Json)[0]
$environment=@{}
foreach($entry in $source.Config.Env){$key,$value=$entry -split '=',2; $environment[$key]=$value}
$environment['RAG_RETRIEVE_TIMEOUT_MS']='65000'
$environment['RAG_RERANK_TIMEOUT_MS']='60000'
$arguments=@('run','-d','--name',$name,'--network','lexagent-release-verify_default','-p','127.0.0.1:19899:8899')
foreach($key in $environment.Keys){$arguments+=@('-e',"$key=$($environment[$key])")}
foreach($mount in $source.Mounts){
 if($mount.Type -eq 'volume'){$spec="type=volume,src=$($mount.Name),dst=$($mount.Destination)"}
 elseif($mount.Type -eq 'bind' -and -not $mount.RW -and $mount.Destination -eq '/app/config.yaml'){$spec="type=bind,src=$($mount.Source),dst=$($mount.Destination)"}
 else{throw 'unexpected mount; inspect first'}
 if(-not $mount.RW){$spec+=',readonly'}
 $arguments+=@('--mount',$spec)
}
$arguments+=$source.Image
docker @arguments|Out-Null
if($LASTEXITCODE -ne 0){throw 'candidate start failed'}
Write-Output "candidate=$name port=19899 retrieve_ms=65000 rerank_ms=60000"
