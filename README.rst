##################################################################
BinaryAlert: Serverless, Real-Time & Retroactive Malware Detection
##################################################################

.. image:: docs/images/logo_plus_thor.png
  :alt: BinaryAlert Logo plus THOR

BinaryAlert is an open-source serverless AWS pipeline where any file uploaded to an S3 bucket is
immediately scanned with a configurable set of `YARA <https://virustotal.github.io/yara/>`_ rules.
An alert will fire as soon as any match is found, giving an incident response team the ability to
quickly contain the threat before it spreads.

Read the documentation at `binaryalert.io <https://binaryalert.io>`_.

****************
THOR integration
****************

This repository fork utilizes THOR in service mode (see `https://www.nextron-systems.com/thor/`) to replace  yextend and yara-python to check for YARA matches. 

.. image:: /docs/images/thor-binary-alert-overview.png 
  :alt: THOR Integration with BinaryAlert

This integration has the following advantages:

* Includes THOR's 10,000+ hand-crafted YARA rule set with focus on 
   * APT related malware 
   * Hack tools 
   * Forensic artefacts 
   * Obfuscation techniques 
   * Web shells
* Special file types supported
   * Registry hives (full walk and IOC application)
   * Memory dumps (full YARA scan)
   * EVTX Eventlogs (log parsing and IOC application)
   * WER files (error report analysis)

You can still use your custom YARA rules along with the THOR encrypted rule set by placing them in the ``./custom-signatures/yara`` sub folder in THOR's program folder. 

============
Requirements
============

This BinaryAlert fork requires 

* a THOR "service" license and 
* a THOR package for Linux with at least version 10.6.0

===============
Gatting Started
===============

Place the contents from the THOR package and your THOR license into ``lambda_functions/analyzer/dependencies.zip``.

=====
Links
=====

- `THOR Scanner <https://www.nextron-systems.com/thor/>`_
- `Announcement Post <https://medium.com/airbnb-engineering/binaryalert-real-time-serverless-malware-detection-ca44370c1b90>`_
- `Documentation <https://binaryalert.io>`_
- `Slack <https://binaryalert.herokuapp.com>`_ (unofficial)
