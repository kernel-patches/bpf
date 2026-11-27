.. SPDX-License-Identifier: GPL-2.0

.. _pt_BR_researcher_guidelines:

Diretrizes para pesquisadores
+++++++++++++++++++++++++++++

A comunidade do kernel Linux dá boas-vindas à pesquisa transparente sobre o
kernel Linux, as atividades envolvidas em sua produção e quaisquer outros
subprodutos de seu desenvolvimento. O Linux se beneficia muito desse tipo de
pesquisa, e a maioria de seus aspectos é impulsionada por pesquisas de uma
forma ou de outra.

A comunidade agradece muito quando pesquisadores compartilham resultados
preliminares antes de torná-los públicos, especialmente se a pesquisa envolver
segurança. O envolvimento antecipado ajuda a melhorar a qualidade da pesquisa
e também a capacidade do Linux de melhorar a partir dela. Em qualquer caso,
recomenda-se compartilhar com a comunidade cópias de acesso aberto dos
trabalhos publicados.

Este documento busca esclarecer quais práticas a comunidade do kernel Linux
considera aceitáveis e inaceitáveis na realização desse tipo de pesquisa. No
mínimo, essas pesquisas e atividades relacionadas devem seguir as regras
padrão de ética em pesquisa. Para saber mais sobre ética em pesquisa em geral,
ética em tecnologia e, em particular, pesquisa sobre comunidades de
desenvolvedores, consulte:

* `História da ética em pesquisa <https://www.unlv.edu/research/ORI-HSR/history-ethics>`_
* `Ética da IEEE <https://www.ieee.org/about/ethics/index.html>`_
* `Perspectivas de desenvolvedores e pesquisadores sobre a ética de experimentos em projetos de código aberto <https://arxiv.org/pdf/2112.13217.pdf>`_

A comunidade do kernel Linux espera que todos que interagem com o projeto
estejam agindo de boa-fé para tornar o Linux melhor. Pesquisas sobre qualquer
artefato produzido pela comunidade do kernel Linux que esteja disponível
publicamente (incluindo, mas não se limitando ao código-fonte) são bem-vindas;
pesquisas sobre desenvolvedores, porém, devem ocorrer somente mediante adesão
explícita dos próprios desenvolvedores.

Pesquisas passivas baseadas inteiramente em fontes disponíveis publicamente,
incluindo publicações em listas de discussão públicas e commits em
repositórios públicos, são claramente permitidas. Ainda assim, como em
qualquer pesquisa, a ética padrão deve ser respeitada.

Pesquisas ativas sobre o comportamento de desenvolvedores, por outro lado,
devem ser realizadas com o acordo explícito dos desenvolvedores envolvidos e
com plena divulgação a cada um deles. Não se pode interagir com
desenvolvedores nem realizar experimentos com eles sem consentimento; isso
também faz parte da ética padrão em pesquisa.

Questionários
=============

Pesquisas frequentemente assumem a forma de questionários enviados a
mantenedores ou colaboradores. Como regra geral, porém, a comunidade do kernel
obtém pouco valor desses questionários. O processo de desenvolvimento do
kernel funciona porque todos os desenvolvedores se beneficiam de sua
participação, inclusive ao trabalhar com outros que têm objetivos diferentes.
Responder a um questionário, porém, é uma demanda unilateral imposta a
desenvolvedores ocupados, sem benefício correspondente para eles ou para a
comunidade do kernel como um todo. Por esse motivo, esse método de pesquisa
é desencorajado.

Os membros da comunidade do kernel já recebem emails em excesso e
provavelmente verão pedidos para responder a questionários como mais uma
demanda por seu tempo. Enviar esses pedidos priva a comunidade do tempo
valioso de seus colaboradores e dificilmente produzirá respostas
estatisticamente úteis.

Como alternativa, pesquisadores devem considerar participar de eventos para
desenvolvedores, organizar sessões em que possam explicar o projeto de
pesquisa e seus benefícios para os participantes e interagir diretamente com
a comunidade nesses eventos. As informações obtidas serão muito mais ricas
que as de um questionário por email, e a comunidade também poderá aprender
com as percepções dos pesquisadores.

Patches
=======

Para esclarecer: enviar patches aos desenvolvedores *é* interagir com eles,
mas eles já consentiram em receber *contribuições de boa-fé*. Não há
consentimento para enviar patches intencionalmente defeituosos ou vulneráveis,
nem para contribuir com informações enganosas nas discussões. Esse tipo de
comunicação pode prejudicar o desenvolvedor (por exemplo, consumindo tempo,
esforço e ânimo) e o projeto, ao corroer a confiança de toda a comunidade de
desenvolvimento no colaborador (e também na organização à qual ele pertence),
prejudicar os esforços para oferecer feedback construtivo aos colaboradores
e expor os usuários finais ao risco de falhas de software.

A participação de pesquisadores no próprio desenvolvimento do Linux, assim
como a de qualquer pessoa, é bem-vinda e incentivada. Pesquisar o código do
Linux é uma prática comum, especialmente ao desenvolver ou executar
ferramentas de análise que produzam resultados acionáveis.

Ao interagir com a comunidade de desenvolvimento, enviar um patch tem sido
tradicionalmente a melhor maneira de causar impacto. O Linux já tem muitos
bugs conhecidos — o que é muito mais útil são correções verificadas. Antes de
contribuir, leia atentamente a documentação apropriada:

* Documentation/process/development-process.rst
* Documentation/process/submitting-patches.rst
* Documentation/admin-guide/reporting-issues.rst
* Documentation/process/security-bugs.rst

Em seguida, envie um patch (incluindo uma mensagem de commit com todos os
detalhes listados abaixo) e acompanhe qualquer feedback de outros
desenvolvedores.

Ao enviar patches produzidos a partir de pesquisas, as mensagens de commit
devem conter pelo menos os detalhes a seguir, para que os desenvolvedores
tenham contexto suficiente para entender a contribuição. Responda:

* Qual é o problema específico encontrado?
* Como se pode chegar a esse problema em um sistema em execução?
* Que efeito a ocorrência do problema teria no sistema?
* Como o problema foi encontrado? Especificamente, inclua detalhes sobre
  quaisquer testes, programas de análise estática ou dinâmica e outras
  ferramentas ou métodos usados no trabalho.
* Em qual versão do Linux o problema foi encontrado? Recomenda-se fortemente
  usar a versão mais recente ou um branch recente do linux-next (veja
  Documentation/process/howto.rst).
* O que foi alterado para corrigir o problema e por que se acredita que a
  correção está correta?
* Como a alteração foi testada em compilação e em tempo de execução?
* Qual commit anterior esta alteração corrige? Isso deve constar em uma tag
  "Fixes:", conforme descrito na documentação.
* Quem mais revisou este patch? Isso deve constar nas tags "Reviewed-by:"
  apropriadas; veja abaixo.

Por exemplo::

  From: Author <author@email>
  Subject: [PATCH] drivers/foo_bar: Add missing kfree()

  The error path in foo_bar driver does not correctly free the allocated
  struct foo_bar_info. This can happen if the attached foo_bar device
  rejects the initialization packets sent during foo_bar_probe(). This
  would result in a 64 byte slab memory leak once per device attach,
  wasting memory resources over time.

  This flaw was found using an experimental static analysis tool we are
  developing, LeakMagic[1], which reported the following warning when
  analyzing the v5.15 kernel release:

   path/to/foo_bar.c:187: missing kfree() call?

  Add the missing kfree() to the error path. No other references to
  this memory exist outside the probe function, so this is the only
  place it can be freed.

  x86_64 and arm64 defconfig builds with CONFIG_FOO_BAR=y using GCC
  11.2 show no new warnings, and LeakMagic no longer warns about this
  code path. As we don't have a FooBar device to test with, no runtime
  testing was able to be performed.

  [1] https://url/to/leakmagic/details

  Reported-by: Researcher <researcher@email>
  Fixes: aaaabbbbccccdddd ("Introduce support for FooBar")
  Signed-off-by: Author <author@email>
  Reviewed-by: Reviewer <reviewer@email>

Se você está contribuindo pela primeira vez, recomenda-se que o patch seja
revisado por outras pessoas em caráter privado antes de ser enviado às listas
públicas. (Isso é obrigatório se tiverem lhe dito explicitamente que seus
patches precisam de uma revisão interna mais cuidadosa.) Espera-se que essas
pessoas tenham a tag "Reviewed-by" incluída no patch resultante. Encontrar
outro desenvolvedor familiarizado com contribuições ao Linux, especialmente
na sua própria organização, e pedir ajuda para revisar antes do envio às
listas públicas tende a melhorar significativamente a qualidade dos patches
e, assim, reduzir a carga de trabalho de outros desenvolvedores.

Se não for possível encontrar alguém para revisar os patches internamente e
você precisar de ajuda para encontrar essa pessoa, ou se tiver outras dúvidas
sobre este documento e as expectativas da comunidade de desenvolvimento,
entre em contato com a lista privada de emails do Conselho Consultivo
Técnico: <tech-board@groups.linuxfoundation.org>.
