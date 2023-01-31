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