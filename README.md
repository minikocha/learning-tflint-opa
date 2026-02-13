# learning-tflint-opa

## 環境設定

1. [mise](https://github.com/jdx/mise)をインストールする

1. miseでツール類をインストールする
    ```
    $ mise install
    ```

1. pythonの仮想環境を作成する
    ```
    $ uv venv .venv
    ```

1. 作成したpythonの仮想環境を有効にする
    ```
    $ . .venv/bin/activate
    ```

1. uvでツール類をインストールする

    ※miseだと依存パッケージまではインストールしてくれないため、敢えて`uv`で管理している。
    ```
    (.venv) $ uv sync
    ```
