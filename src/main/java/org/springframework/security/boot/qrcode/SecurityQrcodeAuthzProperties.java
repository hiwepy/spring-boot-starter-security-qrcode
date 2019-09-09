/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.qrcode;

import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationProcessingFilter;

import lombok.Data;

@Data
public class SecurityQrcodeAuthzProperties {

	public static final String PREFIX = "spring.security.qrcode";

	/** Authorization Path Pattern */
	private String pathPattern = "/authz/login/qrcode";
	private String[] ignorePatterns = new String[] {"/login/jwt"};
	
	/**
	 * Specifies the name of the header on where to find the token (i.e.
	 * X-Authorization).
	 */
	private String authorizationHeaderName = QrcodeAuthorizationProcessingFilter.AUTHORIZATION_HEADER;
	private String authorizationParamName = QrcodeAuthorizationProcessingFilter.AUTHORIZATION_PARAM;
	private String authorizationCookieName = QrcodeAuthorizationProcessingFilter.AUTHORIZATION_PARAM;
	private String qrcodeParamName = QrcodeAuthorizationProcessingFilter.QRCODE_PARAM;
	private boolean useReferer = false;

}