# rpacker
簡易PEファイル用packer

### 対応ファイル形式
- PEファイル (32bit only)

### Options
- -f, --file FILE
    - packするファイル
- -o, --output FILE
    - 出力ファイル名

### 動作概要
    1. PEファイル読み込み
    2. unpacker.exe (unpacker/unpacker.c) コンパイル
    3. 2.に対してPackしたデータを１セクションとして追加
    
### 参考
- https://bidouillesecurity.com/tutorial-writing-a-pe-packer-intro/
- https://zenn.dev/k_kuroguro/articles/f7a63cd08447b6
