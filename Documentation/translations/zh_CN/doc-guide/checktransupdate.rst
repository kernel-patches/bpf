.. SPDX-License-Identifier: GPL-2.0

.. include:: ../disclaimer-zh_CN.rst

:Original: Documentation/doc-guide/checktransupdate.rst

:译者: 慕冬亮 Dongliang Mu <dzm91@hust.edu.cn>

检查翻译更新
============

这个脚本帮助跟踪不同语言的文档翻译状态，判断译文是否需要根据英文原文更新。

工作原理
------------

英文原文与译文在 ``Documentation/`` 和
``Documentation/translations/<locale>/`` 下使用相同的相对路径。例如，
``Documentation/process/foo.rst`` 对应
``Documentation/translations/zh_CN/process/foo.rst``。检查整个语言目录时，
脚本从英文文件出发，报告在对应路径下没有译文的文件。其他路径下的译文不会被
视为该英文文件的翻译。如果单独检查这类译文，脚本会报告找不到同路径的英文原文。
这并不表示该译文中已有的原文路径标注有误。脚本不读取 ``:Original:`` 字段。

脚本使用 ``git log`` 查找译文对应的最新英文提交，以及英文文件在 HEAD 中的
最新提交。它先从翻译提交信息中查找 ``update to commit`` 或
``Update the translation through commit`` 后面的 12 位十六进制提交哈希。
如果没有找到，或指定的提交不在本地 Git 历史中，就按作者日期估计译文所依据的
英文版本。英文原文和译文最初从不同分支合入时，脚本也会使用这一估计。提交日期
被回填或英文原文移动过路径时，这种估计可能不准确。如果两个英文提交不同，脚本
会列出需要检查的提交。

实现的功能

- 检查特定语言中的所有文件
- 检查单个文件或一组文件
- 选择日志级别和日志文件
- 跟踪没有翻译过的文件的翻译状态
- 检查目录中的文件

用法
-----

::

    tools/docs/checktransupdate.py --help

具体用法请参考参数解析器的输出。

示例

-  ``tools/docs/checktransupdate.py -l zh_CN``
   检查 zh_CN 语言中需要更新的文件，并列出尚无译文的英文文件。
-  ``tools/docs/checktransupdate.py Documentation/translations/zh_CN/dev-tools/testing-overview.rst``
   只检查指定文件的状态。
-  ``tools/docs/checktransupdate.py -l sp_SP``
   检查西班牙语译文在对应路径下的更新状态。
-  ``tools/docs/checktransupdate.py Documentation/translations/it_IT/process``
   检查该目录下的译文。

然后输出类似如下的内容：

::

    Documentation/dev-tools/kfence.rst
    No translation in the locale of zh_CN

    Documentation/translations/zh_CN/dev-tools/testing-overview.rst
    commit 42fb9cfd5b18 ("Documentation: dev-tools: Add link to RV docs")
    1 commits needs resolving in total

遇到无法检查的译文时，脚本会立即停止，并以非零状态退出。它无法判断译文内容是否
已经完整反映英文原文；仍需人工检查列出的提交以及相应文件。
