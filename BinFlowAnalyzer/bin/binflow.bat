@REM ----------------------------------------------------------------------------
@REM  Copyright 2001-2006 The Apache Software Foundation.
@REM
@REM  Licensed under the Apache License, Version 2.0 (the "License");
@REM  you may not use this file except in compliance with the License.
@REM  You may obtain a copy of the License at
@REM
@REM       http://www.apache.org/licenses/LICENSE-2.0
@REM
@REM  Unless required by applicable law or agreed to in writing, software
@REM  distributed under the License is distributed on an "AS IS" BASIS,
@REM  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@REM  See the License for the specific language governing permissions and
@REM  limitations under the License.
@REM ----------------------------------------------------------------------------
@REM
@REM   Copyright (c) 2001-2006 The Apache Software Foundation.  All rights
@REM   reserved.

@echo off

set ERROR_CODE=0

:init
@REM Decide how to startup depending on the version of windows

@REM -- Win98ME
if NOT "%OS%"=="Windows_NT" goto Win9xArg

@REM set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" @setlocal

@REM -- 4NT shell
if "%eval[2+2]" == "4" goto 4NTArgs

@REM -- Regular WinNT shell
set CMD_LINE_ARGS=%*
goto WinNTGetScriptDir

@REM The 4NT Shell from jp software
:4NTArgs
set CMD_LINE_ARGS=%$
goto WinNTGetScriptDir

:Win9xArg
@REM Slurp the command line arguments.  This loop allows for an unlimited number
@REM of arguments (up to the command line limit, anyway).
set CMD_LINE_ARGS=
:Win9xApp
if %1a==a goto Win9xGetScriptDir
set CMD_LINE_ARGS=%CMD_LINE_ARGS% %1
shift
goto Win9xApp

:Win9xGetScriptDir
set SAVEDIR=%CD%
%0\
cd %0\..\.. 
set BASEDIR=%CD%
cd %SAVEDIR%
set SAVE_DIR=
goto repoSetup

:WinNTGetScriptDir
set BASEDIR=%~dp0\..

:repoSetup
set REPO=


if "%JAVACMD%"=="" set JAVACMD=java

if "%REPO%"=="" set REPO=%BASEDIR%\repo

set CLASSPATH="%BASEDIR%"\etc;"%REPO%"\org\apache\commons\commons-lang3\3.3.2\commons-lang3-3.3.2.jar;"%REPO%"\com\google\code\gson\gson\2.7\gson-2.7.jar;"%REPO%"\org\antlr\antlr4-runtime\4.3\antlr4-runtime-4.3.jar;"%REPO%"\org\abego\treelayout\org.abego.treelayout.core\1.0.1\org.abego.treelayout.core-1.0.1.jar;"%REPO%"\org\antlr\antlr4-annotations\4.3\antlr4-annotations-4.3.jar;"%REPO%"\commons-cli\commons-cli\1.3.1\commons-cli-1.3.1.jar;"%REPO%"\junit\junit\4.12\junit-4.12.jar;"%REPO%"\org\hamcrest\hamcrest-core\1.3\hamcrest-core-1.3.jar;"%REPO%"\org\jgrapht\jgrapht-core\0.9.1\jgrapht-core-0.9.1.jar;"%REPO%"\org\jgrapht\jgrapht-ext\0.9.1\jgrapht-ext-0.9.1.jar;"%REPO%"\org\tinyjee\jgraphx\jgraphx\2.0.0.1\jgraphx-2.0.0.1.jar;"%REPO%"\jgraph\jgraph\5.13.0.0\jgraph-5.13.0.0.jar;"%REPO%"\com\thoughtworks\xstream\xstream\1.4.8\xstream-1.4.8.jar;"%REPO%"\xmlpull\xmlpull\1.1.3.1\xmlpull-1.1.3.1.jar;"%REPO%"\xpp3\xpp3_min\1.1.4c\xpp3_min-1.1.4c.jar;"%REPO%"\org\codehaus\jettison\jettison\1.3.7\jettison-1.3.7.jar;"%REPO%"\stax\stax-api\1.0.1\stax-api-1.0.1.jar;"%REPO%"\xpp3\xpp3\1.1.4c\xpp3-1.1.4c.jar;"%REPO%"\org\apache\commons\commons-compress\1.10\commons-compress-1.10.jar;"%REPO%"\org\tukaani\xz\1.5\xz-1.5.jar;"%REPO%"\com\esotericsoftware\kryo\kryo\2.24.0\kryo-2.24.0.jar;"%REPO%"\com\esotericsoftware\minlog\minlog\1.2\minlog-1.2.jar;"%REPO%"\org\objenesis\objenesis\2.1\objenesis-2.1.jar;"%REPO%"\log4j\log4j\1.2.17\log4j-1.2.17.jar;"%REPO%"\commons-io\commons-io\2.4\commons-io-2.4.jar;"%REPO%"\dk\brics\automaton\automaton\1.11-8\automaton-1.11-8.jar;"%REPO%"\edu\nccu\soslab\binflow\0.0.3-SNAPSHOT\binflow-0.0.3-SNAPSHOT.jar

set ENDORSED_DIR=
if NOT "%ENDORSED_DIR%" == "" set CLASSPATH="%BASEDIR%"\%ENDORSED_DIR%\*;%CLASSPATH%

if NOT "%CLASSPATH_PREFIX%" == "" set CLASSPATH=%CLASSPATH_PREFIX%;%CLASSPATH%

@REM Reaching here means variables are defined and arguments have been captured
:endInit

%JAVACMD% %JAVA_OPTS%  -classpath %CLASSPATH% -Dapp.name="binflow" -Dapp.repo="%REPO%" -Dapp.home="%BASEDIR%" -Dbasedir="%BASEDIR%" edu.nccu.soslab.binflow.App %CMD_LINE_ARGS%
if %ERRORLEVEL% NEQ 0 goto error
goto end

:error
if "%OS%"=="Windows_NT" @endlocal
set ERROR_CODE=%ERRORLEVEL%

:end
@REM set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" goto endNT

@REM For old DOS remove the set variables from ENV - we assume they were not set
@REM before we started - at least we don't leave any baggage around
set CMD_LINE_ARGS=
goto postExec

:endNT
@REM If error code is set to 1 then the endlocal was done already in :error.
if %ERROR_CODE% EQU 0 @endlocal


:postExec

if "%FORCE_EXIT_ON_ERROR%" == "on" (
  if %ERROR_CODE% NEQ 0 exit %ERROR_CODE%
)

exit /B %ERROR_CODE%
