###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_digital_editions_mult_vuln_jun17_win.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Adobe Digital Editions Multiple Vulnerabilities Jun17 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811116");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-3088", "CVE-2017-3089", "CVE-2017-3093", "CVE-2017-3096",
                "CVE-2017-3090", "CVE-2017-3092", "CVE-2017-3097", "CVE-2017-3094",
                "CVE-2017-3095");
  script_bugtraq_id(99020, 99024, 99021);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-06-20 10:45:13 +0530 (Tue, 20 Jun 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Editions Multiple Vulnerabilities Jun17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Digital Edition
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A memory corruption error.

  - Multiple insecure library loading errors.

  - A stack overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the target system, escalate privileges
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Digital Edition prior to 4.5.5
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb17-20.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!digitalVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:digitalVer, test_version:"4.5.5"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.5");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
