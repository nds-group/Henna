# Henna: Hierarchical Machine Learning Inference in Programmable Switches  

This repository contains the public version of the code for our work Henna, presented at the 1st CONEXT Workshop on Native Network Intelligence (NativeNI), 9 December 2022, Roma, Italy.

# What is Henna?  
<img src="henna_cascaded.jpg" alt="Henna Cascaded Design" style="height: 100px; width:100px;"/>
Henna is a first in-switch implementation of a hierarchical classification system. The concept underpinning our solution is that of splitting a difficult classification task into easier cascaded decisions, which can then be addressed with separated and resource-efficient tree-based classifiers. We propose a design of Henna that aligns with the internal organization of the Protocol Independent Switch Architecture (PISA), and integrates state-of-the-art strategies for mapping decision trees to switch hardware. We then implement Henna into a real testbed with off-the-shelf Intel Tofino programmable switches using the P4 language.  

For more details, please consult our paper: https://doi.org/10.1145/3565009.3569520

# Organization of the repository  


If you make use of this code, kindly cite our paper:  

Aristide Tanyi-Jong Akem, Beyza Bütün, Michele Gucciardo, and Marco Fiore. 2022. Henna: Hierarchical Machine Learning Inference in Programmable Switches. In Native Network Intelligence (NativeNI ’22), December 9, 2022, Roma, Italy. ACM, New York, NY, USA, 7 pages. https://doi.org/10.1145/3565009.3569520


