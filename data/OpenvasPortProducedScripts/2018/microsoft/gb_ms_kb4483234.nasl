###############################################################################
# OpenVAS Vulnerability Test
#
# Scripting Engine Memory Corruption Vulnerability (KB4483234)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
###############################################################################

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814627");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2018-8653");
  script_bugtraq_id(106255);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2018-12-20 13:28:54 +0530 (Thu, 20 Dec 2018)");
  script_name("Scripting Engine Memory Corruption Vulnerability (KB4483234)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4483234");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists because scripting engine
  improperly handles objects in memory in Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user. An attacker who
  successfully exploited the vulnerability could gain the same user rights as the
  current user.");

  script_tag(name:"affected", value:"Windows 10 Version 1803 for 32-bit Systems

  Windows 10 Version 1803 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4483234");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE, nofork: TRUE);
if(!ieVer || ieVer !~ "^11\."){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}

if(version_in_range(version:iedllVer, test_version:"11.0.17134.0", test_version2:"11.0.17134.471"))
{
  report = report_fixed_ver(file_checked:iePath + "\Mshtml.dll",
                            file_version:iedllVer, vulnerable_range:"11.0.17134.0 - 11.0.17134.471");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
