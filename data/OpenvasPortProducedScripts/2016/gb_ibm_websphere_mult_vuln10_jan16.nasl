###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Websphere Application Server Multiple Vulnerabilities -10 Jan16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806838");
  script_version("2019-07-24T08:39:52+0000");
  script_cve_id("CVE-2013-2976", "CVE-2013-2967");
  script_bugtraq_id(61941, 61940);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-01-20 12:31:42 +0530 (Wed, 20 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server Multiple Vulnerabilities -10 Jan16");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An insufficient validation of input by the Administrative console.

  - An improper caching by the Administrative console.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information and remote attacker to inject arbitrary web
  script or HTML.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  6.1 before 6.1.0.47, 7.0 before 7.0.0.29, 8.0 before 8.0.0.7,
  and 8.5 before 8.5.5.0");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) version 6.1.0.47 or 7.0.0.29 or 8.0.0.7 or 8.5.5.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21644047");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www-03.ibm.com/software/products/en/appserv-was");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:wasVer, test_version:"6.1", test_version2:"6.1.0.46"))
{
  fix = "6.1.0.47";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.28"))
{
  fix = "7.0.0.29";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.6"))
{
  fix = "8.0.0.7";
  VULN = TRUE;
}

else if(wasVer =~ "^8\.5")
{
  if(version_is_less(version:wasVer, test_version:"8.5.5.0"))
  {
    fix = "8.5.5.0";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:fix);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
