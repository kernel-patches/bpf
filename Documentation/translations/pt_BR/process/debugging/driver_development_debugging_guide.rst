.. SPDX-License-Identifier: GPL-2.0

======================================================
Conselhos de depuração para desenvolvimento de drivers
======================================================

Este documento serve como ponto de partida geral e material de consulta
para a depuração de drivers de dispositivo.
Embora este guia se concentre na depuração que exige recompilar o
módulo/kernel, o :doc:`guia de depuração a partir do espaço de usuário
<userspace_debugging_guide>` apresenta ferramentas como dynamic debug,
ftrace e outras ferramentas úteis para depurar problemas e comportamentos.
Para conselhos gerais de depuração, veja o :doc:`documento de conselhos
gerais <index>`.

.. contents::
    :depth: 3

As seções a seguir apresentam as ferramentas disponíveis.

printk() e similares
--------------------

São derivados de printf() com destinos variados e com ou sem suporte a
serem ligados ou desligados dinamicamente.

printk() simples
~~~~~~~~~~~~~~~~

O clássico. Pode ser usado com ótimos resultados no desenvolvimento rápido
e improvisado de novos módulos ou para extrair dados arbitrários
necessários à solução de problemas.

Pré-requisito: ``CONFIG_PRINTK`` (geralmente habilitado por padrão)

**Prós**:

- Não é preciso aprender nada, é simples de usar
- Fácil de ajustar exatamente às suas necessidades (formatação dos dados
  (veja: :doc:`/core-api/printk-formats`), visibilidade no log)
- Pode causar atrasos na execução do código (útil para confirmar se a
  temporização é um fator)

**Contras**:

- Exige recompilar o kernel/módulo
- Pode causar atrasos na execução do código (o que pode tornar os
  problemas não reproduzíveis)

Para a documentação completa, veja :doc:`/core-api/printk-basics`

Trace_printk
~~~~~~~~~~~~

Pré-requisito: ``CONFIG_DYNAMIC_FTRACE`` & ``#include <linux/ftrace.h>``

É um pouco menos confortável de usar do que printk(), porque você
precisará ler as mensagens no arquivo de rastreamento (veja:
:ref:`pt_BR_read_ftrace_log`) em vez de no log do kernel, mas é muito
útil quando printk() adiciona atrasos indesejados à execução do código,
tornando os problemas intermitentes ou ocultos.

Se o processamento disso ainda causar problemas de temporização, você
pode tentar trace_puts().

Para a documentação completa, veja trace_printk()

dev_dbg
~~~~~~~

Instrução de print que pode ser controlada pelo
:ref:`translations/pt_BR/process/debugging/userspace_debugging_guide:dynamic debug`
e que contém informações adicionais sobre o dispositivo usado no
contexto.

**Quando é apropriado deixar um print de depuração no código?**

Instruções de depuração permanentes precisam ser úteis para que um
desenvolvedor diagnostique o mau comportamento do driver. Julgar isso é
um pouco mais arte do que ciência, mas há algumas orientações nas
:ref:`diretrizes de estilo de código
<translations/pt_BR/process/coding-style:13) imprimindo mensagens do kernel>`.
Em quase todos os casos, as instruções de depuração não devem ser enviadas
ao upstream, já que se espera que um driver funcionando seja silencioso.

printk customizado
~~~~~~~~~~~~~~~~~~

Exemplo::

  #define core_dbg(fmt, arg...) do { \
	  if (core_debug) \
		  printk(KERN_DEBUG pr_fmt("core: " fmt), ## arg); \
	  } while (0)

**Quando você deveria fazer isso?**

É melhor usar simplesmente um pr_debug(), que pode depois ser ligado ou
desligado com o dynamic debug. Além disso, muitos drivers ativam esses
prints por meio de uma variável como ``core_debug``, definida por um
parâmetro de módulo. No entanto, parâmetros de módulo `não são mais
recomendados
<https://lore.kernel.org/all/2024032757-surcharge-grime-d3dd@gregkh>`_.

Ftrace
------

Criando um tracepoint customizado do Ftrace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Um tracepoint adiciona ao seu código um gancho que será chamado e
registrado quando o tracepoint estiver habilitado. Isso pode ser usado,
por exemplo, para rastrear a passagem por um desvio condicional ou para
despejar o estado interno em pontos específicos do fluxo do código durante
uma sessão de depuração.

Aqui está uma descrição básica de :ref:`como implementar novos tracepoints
<trace/tracepoints:usage>`.

Para a documentação completa do rastreamento de eventos, veja
:doc:`/trace/events`

Para a documentação completa do Ftrace, veja :doc:`/trace/ftrace`

DebugFS
-------

Pré-requisito: ``CONFIG_DEBUG_FS`` & ``#include <linux/debugfs.h>``

O DebugFS difere das outras abordagens de depuração, pois não escreve
mensagens no log do kernel nem adiciona rastros ao código. Em vez disso,
ele permite que o desenvolvedor manipule um conjunto de arquivos.
Com esses arquivos, você pode armazenar valores de variáveis, fazer dumps
de registradores/memória ou tornar esses arquivos graváveis e modificar
valores/configurações no driver.

Possíveis casos de uso, entre outros:

- Armazenar valores de registradores
- Acompanhar variáveis
- Armazenar erros
- Armazenar configurações
- Alternar uma configuração, como ligar/desligar a depuração
- Injeção de erros

Isso é especialmente útil quando o tamanho de um dump de dados seria
difícil de digerir como parte do log geral do kernel (por exemplo, ao
despejar dados brutos de um bitstream) ou quando você não está interessado
em todos os valores o tempo todo, mas quer ter a possibilidade de
inspecioná-los.

A ideia geral é:

- Criar um diretório durante o probe (``struct dentry *parent =
  debugfs_create_dir("my_driver", NULL);``)
- Criar um arquivo (``debugfs_create_u32("my_value", 444, parent,
  &my_variable);``)

  - Neste exemplo, o arquivo fica em
    ``/sys/kernel/debug/my_driver/my_value`` (com permissão de leitura
    para usuário/grupo/todos)
  - qualquer leitura do arquivo retornará o conteúdo atual da variável
    ``my_variable``

- Limpar o diretório ao remover o dispositivo
  (``debugfs_remove(parent);``)

Para a documentação completa, veja :doc:`/filesystems/debugfs`.

KASAN, UBSAN, lockdep e outros verificadores de erros
-----------------------------------------------------

KASAN (Kernel Address Sanitizer)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pré-requisito: ``CONFIG_KASAN``

O KASAN é um detector dinâmico de erros de memória que ajuda a encontrar
bugs de use-after-free e de acesso fora dos limites (out-of-bounds). Ele
usa instrumentação em tempo de compilação para verificar cada acesso à
memória.

Para a documentação completa, veja :doc:`/dev-tools/kasan`.

UBSAN (Undefined Behavior Sanitizer)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pré-requisito: ``CONFIG_UBSAN``

O UBSAN depende de instrumentação do compilador e de verificações em
tempo de execução para detectar comportamento indefinido. Ele foi
projetado para encontrar uma variedade de problemas, incluindo overflow de
inteiros com sinal, índice de array fora dos limites e outros.

Para a documentação completa, veja :doc:`/dev-tools/ubsan`

lockdep (Lock Dependency Validator)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pré-requisito: ``CONFIG_DEBUG_LOCKDEP``

O lockdep é um validador de dependências de locks em tempo de execução
que detecta potenciais deadlocks e outros problemas relacionados a locks
no kernel.
Ele acompanha a aquisição e a liberação de locks, construindo um grafo de
dependências que é analisado em busca de potenciais deadlocks.
O lockdep é especialmente útil para validar se a ordem de aquisição dos
locks no kernel está correta.

PSI (Pressure stall information tracking)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pré-requisito: ``CONFIG_PSI``

O PSI é uma ferramenta de medição para identificar overcommit
excessivo de recursos de hardware, o que pode causar quedas de
desempenho ou até mesmo OOM kills.

device coredump
---------------

Pré-requisito: ``CONFIG_DEV_COREDUMP`` & ``#include <linux/devcoredump.h>``

Fornece a infraestrutura para que um driver entregue dados arbitrários ao
espaço de usuário. É usado com mais frequência em conjunto com o udev ou
com uma aplicação semelhante no espaço de usuário que escute os uevents do
kernel, os quais indicam que o dump está pronto. O udev tem regras para
copiar esse arquivo para algum lugar, para armazenamento e análise de
longo prazo, já que, por padrão, os dados do dump são removidos
automaticamente após 5 minutos. Esses dados são analisados com
ferramentas específicas do driver ou com o GDB.

Um device coredump pode ser criado com uma área de vmalloc, com métodos
de leitura/liberação, ou como uma lista scatter/gather.

Você pode encontrar um exemplo de implementação em:
`drivers/media/platform/qcom/venus/core.c
<https://elixir.bootlin.com/linux/v6.11.6/source/drivers/media/platform/qcom/venus/core.c#L30>`__,
na camada HCI do Bluetooth, em vários drivers de rede sem fio e em vários
drivers DRM.

Interfaces do devcoredump
~~~~~~~~~~~~~~~~~~~~~~~~~

A documentação da API do devcoredump é gerada a partir do código-fonte e
está disponível apenas em inglês, na seção "devcoredump interfaces" do
:doc:`documento original
</process/debugging/driver_development_debugging_guide>`.

**Copyright** ©2024 : Collabora
