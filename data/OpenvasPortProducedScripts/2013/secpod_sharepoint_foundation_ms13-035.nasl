###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Foundation HTML Sanitisation Component XSS Vulnerability (2821818)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
CPE = "cpe:/a:microsoft:sharepoint_foundation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902963");
  script_version("2020-01-07T09:06:32+0000");
  script_bugtraq_id(58883);
  script_cve_id("CVE-2013-1289");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-04-10 11:17:19 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft SharePoint Foundation HTML Sanitisation Component XSS Vulnerability (2821818)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2810059");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-035");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass certain security
  restrictions and conduct cross-site scripting and spoofing attacks.");
  script_tag(name:"affected", value:"Microsoft SharePoint Foundation 2010 Service Pack 1");
  script_tag(name:"insight", value:"Certain unspecified input is not properly sanitized within the HTML
  Sanitation component before being returned to the user. This can be
  exploited to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-035.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## SharePoint Foundation 2010
version = get_app_version(cpe:CPE);
if(!version){
  exit(0);
}

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0";
if(!registry_key_exists(key:key)){
  exit(0);
}

dllPath = registry_get_sz(key:key, item:"Location");
if(dllPath)
{
  dllVer  = fetch_file_version(sysPath:dllPath, file_name:"BIN\Onetutil.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6137.5001"))
    {
      if(!port = get_app_port(cpe: CPE)) port = 0;
      security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
      exit(0);
    }
  }
}
