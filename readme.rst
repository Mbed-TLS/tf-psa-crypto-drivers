#####################
TF PSA Crypto drivers
#####################

************
Introduction
************

This repository contains cryptographic drivers that implement the
PSA Cryptoprocessor Driver Interface, for example, to be further integrated
within `Trusted-Firmware-M`_ based platforms.

The `PSA Cryptoprocessor Driver Interface`_ is designed to interface with a
PSA Crypto core component, such as the reference implementation available
in `TF-PSA-Crypto`_. For more details on the capabilities implemented through
such interfaces please refer directly to their respective documentation.
The PSA Crypto core component exposes PSA Crypto APIs, for example
the `PSA Cryptography API 1.1`_.

********************
Repository structure
********************

PSA Crypto drivers in this repository are organized by vendor.
All vendor implementations are located under the ``/vendor`` directory.
Each vendor has its own subdirectory, which may contain one or more
PSA Crypto drivers provided by that vendor.

A typical layout looks like:

.. code-block:: text

    vendor/
        vendor_a/
            driver_1/
            driver_2/
        vendor_b/
            driver_1/

Each driver resides in its own directory and includes documentation
describing its functionality and usage. The documentation structure
within a vendor directory is defined by the vendor.

**************
Maintainership
**************

This repository is maintained as a shared, collaborative effort within the
open-source community. Each vendor is responsible for maintaining its own
driver code, including updates, fixes, and ongoing support. Drivers are
independently owned by the respective maintainers designated by each vendor.

Code Owners
===========

Arm
^^^

- `Amjad Ouled-Ameur <https://github.com/amjoul01>`__ (`amjad.ouled-ameur@arm.com <amjad.ouled-ameur@arm.com>`__)
- `Antonio de Angelis <https://github.com/adeaarm>`__ (`Antonio.deAngelis@arm.com <Antonio.deAngelis@arm.com>`__)

*******
Testing
*******

There is no common or unified testing framework for PSA Crypto drivers in this
repository. Each vendor is responsible for testing and quality assurance of the
drivers they provide and maintain. Vendors are expected to supply documentation
describing how to test their drivers, including any required tools, test cases
and procedures.

*******
License
*******

The software in this repository is provided under the `BSD-3-Clause license <license.rst>`_.
Other licensing schemes are allowed, as those described by the `OSI licences`_
and explicitly stated in the corresponding source code.

.. note::
   Individual files contain the following tag instead of the full license text.

   SPDX-License-Identifier:    BSD-3-Clause

This enables machine processing of license information based on the SPDX
License Identifiers that are here available: http://spdx.org/licenses/

.. _PSA Cryptography API 1.1: https://developer.arm.com/documentation/ihi0086/latest/
.. _OSI licences: https://opensource.org/licenses
.. _Trusted-Firmware-M : https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git/
.. _PSA Cryptoprocessor Driver Interface: https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/docs/proposed/psa-driver-interface.md
.. _TF-PSA-Crypto: https://github.com/Mbed-TLS/TF-PSA-Crypto/

--------------

SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
