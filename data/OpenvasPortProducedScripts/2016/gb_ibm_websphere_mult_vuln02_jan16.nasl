###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mult_vuln02_jan16.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM Websphere Application Server Multiple Vulnerabilities-02 Jan16
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
  script_oid("1.3.6.1.4.1.25623.1.0.806824");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2012-3306", "CVE-2012-3304", "CVE-2012-3311", "CVE-2012-3325",
                "CVE-2012-4853");
  script_bugtraq_id(55678, 55671, 55309, 56458);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-01-19 11:35:34 +0530 (Tue, 19 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server Multiple Vulnerabilities-02 Jan16");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An improper validation of credentials.

  - No CBIND checks when configuring Federated Repositories for IIOP connections
    and Optimized Local Adapters.

  - No purging of password data from the authentication cache, which has
    unspecified impact and remote attack vectors.

  - The some cross site request forgery vulnerability.

  - An error in administrative console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to traverse directories on the system, to bypass security restrictions,
  to hijack a valid user's session, and leads to information disclosure.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  version 6.1 before 6.1.0.45, 7.0 before 7.0.0.25, 8.0 before 8.0.0.5,
  and 8.5 before 8.5.0.1");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) version  6.1.0.45, or 7.0.0.25, or 8.0.0.5, or 8.5.0.1, or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21611313");

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

if(version_in_range(version:wasVer, test_version:"6.1", test_version2:"6.1.0.44"))
{
  fix = "6.1.0.45";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.24"))
{
  fix = "7.0.0.25";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.4"))
{
  fix = "8.0.0.5";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.0.0"))
{
  fix = "8.5.0.1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver( installed_version:wasVer, fixed_version:fix );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
