# learning-tflint-opa

tflintの[tflint-ruleset-opa](https://github.com/terraform-linters/tflint-ruleset-opa)プラグインを使用して、[checkov](https://github.com/bridgecrewio/checkov)のTerraform用のルールを実装できるか検証する。

## 環境設定

1. [mise](https://github.com/jdx/mise)をインストールする

1. miseでツール類をインストールする
    ```console
    $ mise install
    ```

1. pythonの仮想環境を作成する
    ```console
    $ uv venv .venv
    ```

1. 作成したpythonの仮想環境を有効にする
    ```console
    $ . .venv/bin/activate
    ```

1. uvでツール類をインストールする

    ※miseだと依存パッケージまではインストールしてくれないため、敢えて`uv`で管理している。
    ```console
    (.venv) $ uv sync
    ```

## tflintの実行

1. （初回のみ）初期化を行う
    ```console
    $ tflint --init
    ```

1. 実行する

    - カレントディレクトリに`.tflint.hcl`とlint対象のファイルがある場合
      ```console
      $ tflint
      ```

    - 対象のディレクトリを指定して実行する場合

      `-c`オプションおよび環境変数`TFLINT_OPA_POLICY_DIR`で絶対パスを指定しないと、`.tflint.*`へのパスを対象ディレクトリからの相対パスで解決しようとするため実行に失敗する。
      ```console
      $ REPO_ROOT="$(git rev-parse --show-toplevel)"
      $ TFLINT_OPA_POLICY_DIR="${REPO_ROOT}/.tflint.d/policies/tflint" tflint -c "${REPO_ROOT}/.tflint.hcl" --chdir 対象ディレクトリ
      ```

## tflintによる検知の抑制

- 実行時に抑制する

  - `--disable-rule`オプションで抑制する対象を指定する
    ```console
    $ tflint --disable-rule=抑制対象のルール1 --disable-rule=抑制対象のルール2 ...
    ```

  - `--only`オプションで指定したものの検知するようにする
    ```console
    $ tflint --only=検知対象のルール
    ```

- ファイルで抑制する対象を定義する

  - `.tflint.hcl`に追記し一律で抑制する
    ```hcl
    rule "抑制対象のルール" {
      enabled = false
    }
    ```

  - リソースごとに定義する。
    ```hcl
    # tflint-ignore: 抑制対象のルール
    resource "awscc_s3_bucket" "bucket" {}
    ```

## tflintのテストを実行

`.tflint.hcl`が存在するディレクトリで以下を実行する。
```console
$ TFLINT_OPA_TEST=1 tflint
```
