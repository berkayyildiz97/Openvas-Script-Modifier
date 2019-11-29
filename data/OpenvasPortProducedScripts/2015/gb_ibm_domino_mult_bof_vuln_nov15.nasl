###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_mult_bof_vuln_nov15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# IBM Domino Multiple Buffer Overflow Vulnerabilities - Nov15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806610");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-4994", "CVE-2015-5040");
  script_bugtraq_id(77322, 77324);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-04 11:23:23 +0530 (Wed, 04 Nov 2015)");
  script_name("IBM Domino Multiple Buffer Overflow Vulnerabilities - Nov15");

  script_tag(name:"summary", value:"This host is installed with IBM Domino and
  is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to error in
  processing GIF files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or crash the application.");

  script_tag(name:"affected", value:"IBM Domino 8.5.1 through 8.5.3 before 8.5.3
  FP6 IF10 and 9.x before 9.0.1 FP4 IF3");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF10 or
  9.0.1 FP4 IF3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21969050");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

if(!domVer = get_highest_app_version(cpe:CPE)){
  exit(0);
}

domVer1 = ereg_replace(pattern:"FP", string:domVer, replace: ".");

if(version_in_range(version:domVer1, test_version:"8.5.1", test_version2:"8.5.3.6"))
{
  fix = "8.5.3 FP6 IF10";
  VULN = TRUE;
}

if(version_in_range(version:domVer1, test_version:"9.0", test_version2:"9.0.1.4"))
{
  fix = "9.0.1 FP4 IF3";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed Version: ' + domVer + '\nFixed Version: ' + fix + '\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
