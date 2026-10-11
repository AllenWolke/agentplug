[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$temp = Join-Path $root (".tmp\contract-codegen\" + [guid]::NewGuid().ToString("N"))
$goOut = Join-Path $temp "go"
$pythonOut = Join-Path $temp "python"
New-Item -ItemType Directory -Force -Path $goOut, $pythonOut | Out-Null

try {
    $dockerRoot = $root.Replace('\', '/')
    # Generate from the only authoritative Proto contract.
    # 仅从唯一权威 Proto 契约重新生成代码。
    & docker run --rm -v "${dockerRoot}/contracts/proto:/defs" -v "${dockerRoot}/.tmp/contract-codegen/$((Split-Path $temp -Leaf))/go:/out" `
        namely/protoc-all:1.51_2 -f agent_execution_v2.proto -l go -o /out --go-source-relative
    if ($LASTEXITCODE -ne 0) { throw "Go protobuf generation failed" }
    & docker run --rm -v "${dockerRoot}/contracts/proto:/defs" -v "${dockerRoot}/.tmp/contract-codegen/$((Split-Path $temp -Leaf))/python:/out" `
        namely/protoc-all:1.51_2 -f agent_execution_v2.proto -l python -o /out --with-pyi
    if ($LASTEXITCODE -ne 0) { throw "Python protobuf generation failed" }

    $pairs = @(
        @((Join-Path $goOut "agent_execution_v2.pb.go"), (Join-Path $root "platform\internal\agentgateway\proto\agent_execution_v2.pb.go")),
        @((Join-Path $goOut "agent_execution_v2_grpc.pb.go"), (Join-Path $root "platform\internal\agentgateway\proto\agent_execution_v2_grpc.pb.go")),
        @((Join-Path $pythonOut "agent_execution_v2_pb2.py"), (Join-Path $root "sdk\python\agent_platform_sdk\proto\agent_execution_v2_pb2.py")),
        @((Join-Path $pythonOut "agent_execution_v2_pb2.pyi"), (Join-Path $root "sdk\python\agent_platform_sdk\proto\agent_execution_v2_pb2.pyi")),
        @((Join-Path $pythonOut "agent_execution_v2_pb2_grpc.pyi"), (Join-Path $root "sdk\python\agent_platform_sdk\proto\agent_execution_v2_pb2_grpc.pyi"))
    )
    foreach ($pair in $pairs) {
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[1]).Hash) {
            throw "generated contract drift: $($pair[1])"
        }
    }
    # The package-local relative import is the only intentional Python post-process.
    # 包内相对导入是 Python 生成物唯一允许的确定性后处理。
    $generatedGrpc = (Get-Content -Raw -LiteralPath (Join-Path $pythonOut "agent_execution_v2_pb2_grpc.py")) -replace '(?m)^import agent_execution_v2_pb2', 'from . import agent_execution_v2_pb2'
    $storedGrpc = Get-Content -Raw -LiteralPath (Join-Path $root "sdk\python\agent_platform_sdk\proto\agent_execution_v2_pb2_grpc.py")
    if ($generatedGrpc -ne $storedGrpc) { throw "generated Python gRPC contract drift" }
    Write-Host "protobuf generated-code gate passed"
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
