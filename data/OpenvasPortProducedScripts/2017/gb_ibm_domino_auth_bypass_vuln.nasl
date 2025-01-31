###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_auth_bypass_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# IBM Domino Authentication Bypass Vulnerability
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809885");
  script_version("$Revision: 11863 $");
  script_bugtraq_id(96062);
  script_cve_id("CVE-2016-0270");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-15 14:45:56 +0530 (Wed, 15 Feb 2017)");
  script_name("IBM Domino Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with IBM Domino and
  is prone to authentication bypass vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error as for very large
  data sets, IBM Domino Web servers using 'TLS' and 'AES GCM' generate a weak
  nonce.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain the authentication key and spoof data by leveraging the reuse of a
  nonce in a session and a 'forbidden attack.'.");

  script_tag(name:"affected", value:"IBM Domino 9.0.1 Fix Pack 3 Interim Fix 2
  through 9.0.1 Fix Pack 5 Interim Fix 1.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 9.0.1 FP5 Interim Fix 2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979604");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
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

if(domVer1 =~ "^(9\.0\.1)")
{
  if(version_in_range(version:domVer1, test_version:"9.0.1.3", test_version2:"9.0.1.5"))
  {
    report = report_fixed_ver(installed_version:domVer, fixed_version:"9.0.1 FP5 IF2");
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}
