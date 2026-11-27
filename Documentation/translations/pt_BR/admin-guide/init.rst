.. SPDX-License-Identifier: GPL-2.0

Explicando a mensagem de travamento na inicialização: "No working init found."
==============================================================================
:Autores: Andreas Mohr <andi at lisas period de>
          Cristian Souza <cristianmsbr at gmail period com>

Este documento apresenta algumas causas gerais da falha ao carregar o binário
init (listadas aproximadamente na ordem em que ocorrem).

1) **Não foi possível montar o sistema de arquivos raiz**: Defina o parâmetro
   do kernel "debug" (no arquivo de configuração do carregador de inicialização
   ou em CONFIG_CMDLINE) para obter mensagens mais detalhadas do kernel.

2) **O binário init não existe no sistema de arquivos raiz**: Certifique-se de
   que o tipo do sistema de arquivos raiz está correto (e de que o parâmetro
   do kernel ``root=`` aponta para a partição correta) e de que os drivers
   necessários, como os de hardware de armazenamento (por exemplo, SCSI ou
   USB!) e os de sistema de arquivos (ext3, jffs2 etc.), são compilados no
   kernel (ou, alternativamente, estão disponíveis como módulos a serem
   pré-carregados por um initrd).

3) **Dispositivo de console com problemas**: Possivelmente há um conflito na
   configuração de ``console=`` que deixa o console inicial indisponível. Por
   exemplo, alguns consoles seriais não são confiáveis devido a problemas com
   IRQs seriais (por exemplo, ausência de configuração baseada em interrupções).
   Tente especificar outro dispositivo no parâmetro ``console=`` ou, por
   exemplo, usar ``netconsole=``.

4) **O binário existe, mas as dependências não estão disponíveis**: Por
   exemplo, bibliotecas necessárias ao binário init, como
   ``/lib/ld-linux.so.2``, podem estar ausentes ou danificadas. Use
   ``readelf -d <INIT>|grep NEEDED`` para descobrir quais bibliotecas são
   necessárias.

5) **Não é possível carregar o binário**: Certifique-se de que a arquitetura
   do binário corresponda à do hardware. Por exemplo, pode haver uma
   incompatibilidade entre i386 e x86_64 ou uma tentativa de carregar um binário
   x86 em hardware ARM. Se você tentou carregar aqui um arquivo que não é
   binário (um script de shell?), certifique-se de que o script
   especifique um interpretador na linha de shebang do script (``#!/...``)
   que funcione corretamente, incluindo suas dependências de
   biblioteca. Antes de investigar scripts, é melhor testar primeiro um
   binário simples que não seja um script, como ``/bin/sh``, e confirmar que
   ele é executado com sucesso. Para saber mais, adicione código a
   ``init/main.c`` para exibir os valores de retorno de kernel_execve().

Amplie esta explicação sempre que encontrar novas causas de falha (afinal,
carregar o binário init é uma etapa de transição CRÍTICA e difícil, que deve ser
tornada o mais simples possível); em seguida, envie um patch à LKML.
Outras tarefas pendentes:

- Implementar as várias chamadas de ``run_init_process()`` usando um array de
  estruturas, para armazenar o valor de retorno de cada chamada a
  ``kernel_execve()`` e, em caso de falha, percorrer **todos** os resultados e
  registrá-los (uma correção de usabilidade muito importante).
- Tentar tornar a própria implementação mais útil em geral, por exemplo,
  fornecendo mensagens de erro adicionais nos pontos afetados.
