###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (3003057)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804790");
  script_version("2019-12-20T12:48:41+0000");
  script_cve_id("CVE-2014-4143", "CVE-2014-6323", "CVE-2014-6337", "CVE-2014-6339",
                "CVE-2014-6340", "CVE-2014-6341", "CVE-2014-6342", "CVE-2014-6343",
                "CVE-2014-6344", "CVE-2014-6345", "CVE-2014-6346", "CVE-2014-6347",
                "CVE-2014-6348", "CVE-2014-6349", "CVE-2014-6350", "CVE-2014-6351",
                "CVE-2014-6353");
  script_bugtraq_id(70345, 70947, 70337, 70948, 70941, 70338, 70341, 70344,
                    70346, 70942, 70946, 70347, 70348, 70939, 70940, 70323, 70333);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-20 12:48:41 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2014-11-12 08:00:12 +0530 (Wed, 12 Nov 2014)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (3003057)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS14-065.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to multiple unspecified
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information, bypass certain security
  restrictions, and compromise a user's system.");

  script_tag(name:"affected", value:"- Microsoft Internet Explorer version
  6.x/7.x/8.x/9.x/10.x/11.x");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3003057");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-065");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^([6-9|1[01])\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5458") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21414")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23635")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19211")||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23516")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19574")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23632")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16591")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20707")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.17000", test_version2:"8.0.7601.18659")||
     version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.22866")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16591")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20707")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17172")||
     version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21290")||
     version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.17419")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17172")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21290")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.9600.17415")){
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  }
  exit(0);
}
