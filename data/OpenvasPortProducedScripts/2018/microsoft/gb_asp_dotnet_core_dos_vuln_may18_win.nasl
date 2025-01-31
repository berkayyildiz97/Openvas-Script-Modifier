###############################################################################
# OpenVAS Vulnerability Test
#
# ASP.NET Core Denial of Service Vulnerability May18 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
##########################################################################
CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813189");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-0765");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-15 14:16:59 +0530 (Tue, 15 May 2018)");
  script_name("ASP.NET Core Denial of Service Vulnerability May18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with ASP.NET Core
  and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error when .NET
  and .NET Core improperly process XML documents.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a denial of service against a .NET application.");

  script_tag(name:"affected", value:"ASP.NET Core 2.0 prior to version 2.0.8");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core 2.0 to version
  2.0.8 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0765");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/67");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/download-archives/2.1.200-sdk-download.md");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE, version_regex:"[0-9]+\.[0-9]+\.[0-9]+")) exit(0);
coreVers = infos['version'];
path = infos['location'];

if(coreVers =~ "^(2\.0)" && version_is_less(version:coreVers, test_version:"2.0.8"))
{
  report = report_fixed_ver(installed_version:coreVers, fixed_version:"2.0.8", install_path:path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
