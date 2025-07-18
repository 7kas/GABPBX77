/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2012, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.gabpbx.org for more information about
 * the GABpbx project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief dial() & retrydial() - Trivial application to dial a channel and send an URL on answer
 *
 * \author Mark Spencer <markster@digium.com>
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/


#include "gabpbx.h"

#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include "gabpbx/paths.h" /* use ast_config_AST_DATA_DIR */
#include "gabpbx/lock.h"
#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/module.h"
#include "gabpbx/translate.h"
#include "gabpbx/say.h"
#include "gabpbx/config.h"
#include "gabpbx/features.h"
#include "gabpbx/musiconhold.h"
#include "gabpbx/callerid.h"
#include "gabpbx/utils.h"
#include "gabpbx/app.h"
#include "gabpbx/causes.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/manager.h"
#include "gabpbx/privacy.h"
#include "gabpbx/stringfields.h"
#include "gabpbx/dsp.h"
#include "gabpbx/aoc.h"
#include "gabpbx/ccss.h"
#include "gabpbx/indications.h"
#include "gabpbx/framehook.h"
#include "gabpbx/dial.h"
#include "gabpbx/stasis_channels.h"
#include "gabpbx/bridge_after.h"
#include "gabpbx/features_config.h"
#include "gabpbx/max_forwards.h"
#include "gabpbx/stream.h"

/*** DOCUMENTATION
	<application name="Dial" language="en_US">
		<since>
			<version>0.1.0</version>
		</since>
		<synopsis>
			Attempt to connect to another device or endpoint and bridge the call.
		</synopsis>
		<syntax>
			<parameter name="Technology/Resource" required="false" argsep="&amp;">
				<argument name="Technology/Resource" required="true">
					<para>Specification of the device(s) to dial.  These must be in the format of
					<literal>Technology/Resource</literal>, where <replaceable>Technology</replaceable>
					represents a particular channel driver, and <replaceable>Resource</replaceable>
					represents a resource available to that particular channel driver.</para>
				</argument>
				<argument name="Technology2/Resource2" required="false" multiple="true">
					<para>Optional extra devices to dial in parallel</para>
					<para>If you need more than one enter them as
					Technology2/Resource2&amp;Technology3/Resource3&amp;.....</para>
				</argument>
				<xi:include xpointer="xpointer(/docs/info[@name='Dial_Resource'])" />
			</parameter>
			<parameter name="timeout" required="false" argsep="^">
				<para>Specifies the number of seconds we attempt to dial the specified devices.</para>
				<para>If not specified, this defaults to 136 years.</para>
				<para>If a second argument is specified, this controls the number of seconds we attempt to dial the specified devices
				without receiving early media or ringing. If neither progress, ringing, nor voice frames have been received when this
				timeout expires, the call will be treated as a CHANUNAVAIL. This can be used to skip destinations that may not be responsive.</para>
			</parameter>
			<parameter name="options" required="false">
				<optionlist>
				<option name="A" argsep=":">
					<argument name="x">
						<para>The file to play to the called party</para>
					</argument>
					<argument name="y">
						<para>The file to play to the calling party</para>
					</argument>
					<para>Play an announcement to the called and/or calling parties, where <replaceable>x</replaceable>
					is the prompt to be played to the called party and <replaceable>y</replaceable> is the prompt
					to be played to the caller. The files may be different and will be played to each party
					simultaneously.</para>
				</option>
				<option name="a">
					<para>Immediately answer the calling channel when the called channel answers in
					all cases. Normally, the calling channel is answered when the called channel
					answers, but when options such as <literal>A()</literal> and
					<literal>M()</literal> are used, the calling channel is
					not answered until all actions on the called channel (such as playing an
					announcement) are completed.  This option can be used to answer the calling
					channel before doing anything on the called channel. You will rarely need to use
					this option, the default behavior is adequate in most cases.</para>
				</option>
				<option name="b" argsep="^">
					<para>Before initiating an outgoing call, <literal>Gosub</literal> to the specified
					location using the newly created channel.  The <literal>Gosub</literal> will be
					executed for each destination channel.</para>
					<argument name="context" required="false" />
					<argument name="exten" required="false" />
					<argument name="priority" required="true" hasparams="optional" argsep="^">
						<argument name="arg1" multiple="true" required="true" />
						<argument name="argN" />
					</argument>
				</option>
				<option name="B" argsep="^">
					<para>Before initiating the outgoing call(s), <literal>Gosub</literal> to the
					specified location using the current channel.</para>
					<argument name="context" required="false" />
					<argument name="exten" required="false" />
					<argument name="priority" required="true" hasparams="optional" argsep="^">
						<argument name="arg1" multiple="true" required="true" />
						<argument name="argN" />
					</argument>
				</option>
				<option name="C">
					<para>Reset the call detail record (CDR) for this call.</para>
				</option>
				<option name="c">
					<para>If the Dial() application cancels this call, always set
					<variable>HANGUPCAUSE</variable> to 'answered elsewhere'</para>
				</option>
				<option name="d">
					<para>Allow the calling user to dial a 1 digit extension while waiting for
					a call to be answered. Exit to that extension if it exists in the
					current context, or the context defined in the <variable>EXITCONTEXT</variable> variable,
					if it exists.</para>
					<para>NOTE: Many SIP and ISDN phones cannot send DTMF digits until the call is
					connected.  If you wish to use this option with these phones, you
					can use the <literal>Answer</literal> application before dialing.</para>
				</option>
				<option name="D" argsep=":">
					<argument name="called" />
					<argument name="calling" />
					<argument name="progress" />
					<argument name="mfprogress" />
					<argument name="mfwink" />
					<argument name="sfprogress" />
					<argument name="sfwink" />
					<para>Send the specified DTMF strings <emphasis>after</emphasis> the called
					party has answered, but before the call gets bridged.  The
					<replaceable>called</replaceable> DTMF string is sent to the called party, and the
					<replaceable>calling</replaceable> DTMF string is sent to the calling party.  Both arguments
					can be used alone.  If <replaceable>progress</replaceable> is specified, its DTMF is sent
					to the called party immediately after receiving a <literal>PROGRESS</literal> message.</para>
					<para>See <literal>SendDTMF</literal> for valid digits.</para>
					<para>If <replaceable>mfprogress</replaceable> is specified, its MF is sent
					to the called party immediately after receiving a <literal>PROGRESS</literal> message.
					If <replaceable>mfwink</replaceable> is specified, its MF is sent
					to the called party immediately after receiving a <literal>WINK</literal> message.</para>
					<para>See <literal>SendMF</literal> for valid digits.</para>
					<para>If <replaceable>sfprogress</replaceable> is specified, its SF is sent
					to the called party immediately after receiving a <literal>PROGRESS</literal> message.
					If <replaceable>sfwink</replaceable> is specified, its SF is sent
					to the called party immediately after receiving a <literal>WINK</literal> message.</para>
					<para>See <literal>SendSF</literal> for valid digits.</para>
				</option>
				<option name="E">
					<para>Enable echoing of sent MF or SF digits back to caller (e.g. "hearpulsing").
					Used in conjunction with the D option.</para>
				</option>
				<option name="e">
					<para>Execute the <literal>h</literal> extension for peer after the call ends</para>
				</option>
				<option name="f">
					<argument name="x" required="false" />
					<para>If <replaceable>x</replaceable> is not provided, force the CallerID sent on a call-forward or
					deflection to the dialplan extension of this <literal>Dial()</literal> using a dialplan <literal>hint</literal>.
					For example, some PSTNs do not allow CallerID to be set to anything
					other than the numbers assigned to you.
					If <replaceable>x</replaceable> is provided, force the CallerID sent to <replaceable>x</replaceable>.</para>
				</option>
				<option name="F" argsep="^">
					<argument name="context" required="false" />
					<argument name="exten" required="false" />
					<argument name="priority" required="true" />
					<para>When the caller hangs up, transfer the <emphasis>called</emphasis> party
					to the specified destination and <emphasis>start</emphasis> execution at that location.</para>
					<para>NOTE: Any channel variables you want the called channel to inherit from the caller channel must be
					prefixed with one or two underbars ('_').</para>
				</option>
				<option name="F">
					<para>When the caller hangs up, transfer the <emphasis>called</emphasis> party to the next priority of the current extension
					and <emphasis>start</emphasis> execution at that location.</para>
					<para>NOTE: Any channel variables you want the called channel to inherit from the caller channel must be
					prefixed with one or two underbars ('_').</para>
					<para>NOTE: Using this option from a GoSub() might not make sense as there would be no return points.</para>
				</option>
				<option name="g">
					<para>Proceed with dialplan execution at the next priority in the current extension if the
					destination channel hangs up.</para>
				</option>
				<option name="G" argsep="^">
					<argument name="context" required="false" />
					<argument name="exten" required="false" />
					<argument name="priority" required="true" />
					<para>If the call is answered, transfer the calling party to
					the specified <replaceable>priority</replaceable> and the called party to the specified
					<replaceable>priority</replaceable> plus one.</para>
					<para>NOTE: You cannot use any additional action post answer options in conjunction with this option.</para>
				</option>
				<option name="h">
					<para>Allow the called party to hang up by sending the DTMF sequence
					defined for disconnect in <filename>features.conf</filename>.</para>
				</option>
				<option name="H">
					<para>Allow the calling party to hang up by sending the DTMF sequence
					defined for disconnect in <filename>features.conf</filename>.</para>
					<para>NOTE: Many SIP and ISDN phones cannot send DTMF digits until the call is
					connected.  If you wish to allow DTMF disconnect before the dialed
					party answers with these phones, you can use the <literal>Answer</literal>
					application before dialing.</para>
				</option>
				<option name="i">
					<para>GABpbx will ignore any forwarding requests it may receive on this dial attempt.</para>
				</option>
				<option name="I">
					<para>GABpbx will ignore any connected line update requests or any redirecting party
					update requests it may receive on this dial attempt.</para>
				</option>
				<option name="j">
					<para>Use the initial stream topology of the caller for outgoing channels, even if the caller topology has changed.</para>
					<para>NOTE: For this option to work, it has to be present in all invocations of Dial that the caller channel goes through.</para>
				</option>
				<option name="k">
					<para>Allow the called party to enable parking of the call by sending
					the DTMF sequence defined for call parking in <filename>features.conf</filename>.</para>
				</option>
				<option name="K">
					<para>Allow the calling party to enable parking of the call by sending
					the DTMF sequence defined for call parking in <filename>features.conf</filename>.</para>
				</option>
				<option name="L" argsep=":">
					<argument name="x" required="true">
						<para>Maximum call time, in milliseconds</para>
					</argument>
					<argument name="y">
						<para>Warning time, in milliseconds</para>
					</argument>
					<argument name="z">
						<para>Repeat time, in milliseconds</para>
					</argument>
					<para>Limit the call to <replaceable>x</replaceable> milliseconds. Play a warning when <replaceable>y</replaceable> milliseconds are
					left. Repeat the warning every <replaceable>z</replaceable> milliseconds until time expires.</para>
					<para>This option is affected by the following variables:</para>
					<variablelist>
						<variable name="LIMIT_PLAYAUDIO_CALLER">
							<value name="yes" default="true" />
							<value name="no" />
							<para>If set, this variable causes GABpbx to play the prompts to the caller.</para>
						</variable>
						<variable name="LIMIT_PLAYAUDIO_CALLEE">
							<value name="yes" />
							<value name="no" default="true"/>
							<para>If set, this variable causes GABpbx to play the prompts to the callee.</para>
						</variable>
						<variable name="LIMIT_TIMEOUT_FILE">
							<value name="filename"/>
							<para>If specified, <replaceable>filename</replaceable> specifies the sound prompt to play when the timeout is reached.
							If not set, the time remaining will be announced.</para>
						</variable>
						<variable name="LIMIT_CONNECT_FILE">
							<value name="filename"/>
							<para>If specified, <replaceable>filename</replaceable> specifies the sound prompt to play when the call begins.
							If not set, the time remaining will be announced.</para>
						</variable>
						<variable name="LIMIT_WARNING_FILE">
							<value name="filename"/>
							<para>If specified, <replaceable>filename</replaceable> specifies the sound prompt to play as
							a warning when time <replaceable>x</replaceable> is reached. If not set, the time remaining will be announced.</para>
						</variable>
					</variablelist>
				</option>
				<option name="m">
					<argument name="class" required="false"/>
					<para>Provide hold music to the calling party until a requested
					channel answers. A specific music on hold <replaceable>class</replaceable>
					(as defined in <filename>musiconhold.conf</filename>) can be specified.</para>
				</option>
				<option name="n">
					<argument name="delete">
						<para>With <replaceable>delete</replaceable> either not specified or set to <literal>0</literal>,
						the recorded introduction will not be deleted if the caller hangs up while the remote party has not
						yet answered.</para>
						<para>With <replaceable>delete</replaceable> set to <literal>1</literal>, the introduction will
						always be deleted.</para>
					</argument>
					<para>This option is a modifier for the call screening/privacy mode. (See the
					<literal>p</literal> and <literal>P</literal> options.) It specifies
					that no introductions are to be saved in the <directory>priv-callerintros</directory>
					directory.</para>
				</option>
				<option name="N">
					<para>This option is a modifier for the call screening/privacy mode. It specifies
					that if CallerID is present, do not screen the call.</para>
				</option>
				<option name="o">
					<argument name="x" required="false" />
					<para>If <replaceable>x</replaceable> is not provided, specify that the CallerID that was present on the
					<emphasis>calling</emphasis> channel be stored as the CallerID on the <emphasis>called</emphasis> channel.
					This was the behavior of GABpbx 1.0 and earlier.
					If <replaceable>x</replaceable> is provided, specify the CallerID stored on the <emphasis>called</emphasis> channel.
					Note that <literal>o(${CALLERID(all)})</literal> is similar to option <literal>o</literal> without the parameter.</para>
				</option>
				<option name="O">
					<argument name="mode">
						<para>With <replaceable>mode</replaceable> either not specified or set to <literal>1</literal>,
						the originator hanging up will cause the phone to ring back immediately.</para>
						<para>With <replaceable>mode</replaceable> set to <literal>2</literal>, when the operator
						flashes the trunk, it will ring their phone back.</para>
					</argument>
					<para>Enables <emphasis>operator services</emphasis> mode.  This option only
					works when bridging a DAHDI channel to another DAHDI channel
					only. If specified on non-DAHDI interfaces, it will be ignored.
					When the destination answers (presumably an operator services
					station), the originator no longer has control of their line.
					They may hang up, but the switch will not release their line
					until the destination party (the operator) hangs up.</para>
				</option>
				<option name="p">
					<para>This option enables screening mode. This is basically Privacy mode
					without memory.</para>
				</option>
				<option name="P">
					<argument name="x" />
					<para>Enable privacy mode. Use <replaceable>x</replaceable> as the family/key in the AstDB database if
					it is provided. The current extension is used if a database family/key is not specified.</para>
				</option>
				<option name="Q">
					<argument name="cause" required="true"/>
					<para>Specify the Q.850/Q.931 <replaceable>cause</replaceable> to send on
					unanswered channels when another channel answers the call.
					As with <literal>Hangup()</literal>, <replaceable>cause</replaceable>
					can be a numeric cause code or a name such as
						<literal>NO_ANSWER</literal>,
						<literal>USER_BUSY</literal>,
						<literal>CALL_REJECTED</literal> or
						<literal>ANSWERED_ELSEWHERE</literal> (the default if Q isn't specified).
						You can also specify <literal>0</literal> or <literal>NONE</literal>
						to send no cause.  See the <filename>causes.h</filename> file for the
						full list of valid causes and names.
						</para>
				</option>
				<option name="r">
					<para>Default: Indicate ringing to the calling party, even if the called party isn't actually ringing. Pass no audio to the calling
					party until the called channel has answered.</para>
					<argument name="tone" required="false">
						<para>Indicate progress to calling party. Send audio 'tone' from the <filename>indications.conf</filename> tonezone currently in use.</para>
					</argument>
				</option>
				<option name="R">
					<para>Default: Indicate ringing to the calling party, even if the called party isn't actually ringing.
					Allow interruption of the ringback if early media is received on the channel.</para>
				</option>
				<option name="S">
					<argument name="x" required="true" />
					<para>Hang up the call <replaceable>x</replaceable> seconds <emphasis>after</emphasis> the called party has
					answered the call.</para>
				</option>
				<option name="s">
					<argument name="x" required="true" />
					<para>Force the outgoing CallerID tag parameter to be set to the string <replaceable>x</replaceable>.</para>
					<para>Works with the <literal>f</literal> option.</para>
				</option>
				<option name="t">
					<para>Allow the called party to transfer the calling party by sending the
					DTMF sequence defined in <filename>features.conf</filename>. This setting does not perform policy enforcement on
					transfers initiated by other methods.</para>
				</option>
				<option name="T">
					<para>Allow the calling party to transfer the called party by sending the
					DTMF sequence defined in <filename>features.conf</filename>. This setting does not perform policy enforcement on
					transfers initiated by other methods.</para>
				</option>
				<option name="U" argsep="^">
					<argument name="x" required="true">
						<para>Name of the subroutine context to execute via <literal>Gosub</literal>.
						The subroutine execution starts in the named context at the s exten and priority 1.</para>
					</argument>
					<argument name="arg" multiple="true" required="false">
						<para>Arguments for the <literal>Gosub</literal> routine</para>
					</argument>
					<para>Execute via <literal>Gosub</literal> the routine <replaceable>x</replaceable> for the <emphasis>called</emphasis> channel before connecting
					to the calling channel. Arguments can be specified to the <literal>Gosub</literal>
					using <literal>^</literal> as a delimiter. The <literal>Gosub</literal> routine can set the variable
					<variable>GOSUB_RESULT</variable> to specify the following actions after the <literal>Gosub</literal> returns.</para>
					<variablelist>
						<variable name="GOSUB_RESULT">
							<value name="ABORT">
								Hangup both legs of the call.
							</value>
							<value name="CONGESTION">
								Behave as if line congestion was encountered.
							</value>
							<value name="BUSY">
								Behave as if a busy signal was encountered.
							</value>
							<value name="CONTINUE">
								Hangup the called party and allow the calling party
								to continue dialplan execution at the next priority.
							</value>
							<value name="GOTO:[[&lt;context&gt;^]&lt;exten&gt;^]&lt;priority&gt;">
								Transfer the call to the specified destination.
							</value>
						</variable>
					</variablelist>
					<para>NOTE: You cannot use any additional action post answer options in conjunction
					with this option. Also, pbx services are run on the <emphasis>called</emphasis> channel,
					so you will not be able to set timeouts via the <literal>TIMEOUT()</literal> function in this routine.</para>
				</option>
				<option name="u">
					<argument name = "x" required="true">
						<para>Force the outgoing callerid presentation indicator parameter to be set
						to one of the values passed in <replaceable>x</replaceable>:
						<literal>allowed_not_screened</literal>
						<literal>allowed_passed_screen</literal>
						<literal>allowed_failed_screen</literal>
						<literal>allowed</literal>
						<literal>prohib_not_screened</literal>
						<literal>prohib_passed_screen</literal>
						<literal>prohib_failed_screen</literal>
						<literal>prohib</literal>
						<literal>unavailable</literal></para>
					</argument>
					<para>Works with the <literal>f</literal> option.</para>
				</option>
				<option name="w">
					<para>Allow the called party to enable recording of the call by sending
					the DTMF sequence defined for one-touch recording in <filename>features.conf</filename>.</para>
				</option>
				<option name="W">
					<para>Allow the calling party to enable recording of the call by sending
					the DTMF sequence defined for one-touch recording in <filename>features.conf</filename>.</para>
				</option>
				<option name="x">
					<para>Allow the called party to enable recording of the call by sending
					the DTMF sequence defined for one-touch automixmonitor in <filename>features.conf</filename>.</para>
				</option>
				<option name="X">
					<para>Allow the calling party to enable recording of the call by sending
					the DTMF sequence defined for one-touch automixmonitor in <filename>features.conf</filename>.</para>
				</option>
				<option name="z">
					<para>On a call forward, cancel any dial timeout which has been set for this call.</para>
				</option>
				</optionlist>
			</parameter>
			<parameter name="URL">
				<para>The optional URL will be sent to the called party if the channel driver supports it.</para>
			</parameter>
		</syntax>
		<description>
			<para>This application will place calls to one or more specified channels. As soon
			as one of the requested channels answers, the originating channel will be
			answered, if it has not already been answered. These two channels will then
			be active in a bridged call. All other channels that were requested will then
			be hung up.</para>
			<para>Unless there is a timeout specified, the Dial application will wait
			indefinitely until one of the called channels answers, the user hangs up, or
			if all of the called channels are busy or unavailable. Dialplan execution will
			continue if no requested channels can be called, or if the timeout expires.
			This application will report normal termination if the originating channel
			hangs up, or if the call is bridged and either of the parties in the bridge
			ends the call.</para>
			<para>If the <variable>OUTBOUND_GROUP</variable> variable is set, all peer channels created by this
			application will be put into that group (as in <literal>Set(GROUP()=...</literal>).
			If the <variable>OUTBOUND_GROUP_ONCE</variable> variable is set, all peer channels created by this
			application will be put into that group (as in <literal>Set(GROUP()=...</literal>). Unlike <variable>OUTBOUND_GROUP</variable>,
			however, the variable will be unset after use.</para>
			<example title="Dial with 30 second timeout">
			 same => n,Dial(PJSIP/alice,30)
			</example>
			<example title="Parallel dial with 45 second timeout">
			 same => n,Dial(PJSIP/alice&amp;PJIP/bob,45)
			</example>
			<example title="Dial with 'g' continuation option">
			 same => n,Dial(PJSIP/alice,,g)
			 same => n,Log(NOTICE, Alice call result: ${DIALSTATUS})
			</example>
			<example title="Dial with transfer/recording features for calling party">
			 same => n,Dial(PJSIP/alice,,TX)
			</example>
			<example title="Dial with call length limit">
			 same => n,Dial(PJSIP/alice,,L(60000:30000:10000))
			</example>
			<example title="Dial alice and bob and send NO_ANSWER to bob instead of ANSWERED_ELSEWHERE when alice answers">
			 same => n,Dial(PJSIP/alice&amp;PJSIP/bob,,Q(NO_ANSWER))
			</example>
			<example title="Dial with pre-dial subroutines">
			[default]
			exten => callee_channel,1,NoOp(ARG1=${ARG1} ARG2=${ARG2})
			 same => n,Log(NOTICE, I'm called on channel ${CHANNEL} prior to it starting the dial attempt)
			 same => n,Return()
			exten => called_channel,1,NoOp(ARG1=${ARG1} ARG2=${ARG2})
			 same => n,Log(NOTICE, I'm called on outbound channel ${CHANNEL} prior to it being used to dial someone)
			 same => n,Return()
			exten => _X.,1,NoOp()
			 same => n,Dial(PJSIP/alice,,b(default^called_channel^1(my_gosub_arg1^my_gosub_arg2))B(default^callee_channel^1(my_gosub_arg1^my_gosub_arg2)))
			 same => n,Hangup()
			</example>
			<example title="Dial with post-answer subroutine executed on outbound channel">
			[my_gosub_routine]
			exten => s,1,NoOp(ARG1=${ARG1} ARG2=${ARG2})
			 same => n,Playback(hello)
			 same => n,Return()
			[default]
			exten => _X.,1,NoOp()
			 same => n,Dial(PJSIP/alice,,U(my_gosub_routine^my_gosub_arg1^my_gosub_arg2))
			 same => n,Hangup()
			</example>
			<example title="Dial into ConfBridge using 'G' option">
			 same => n,Dial(PJSIP/alice,,G(jump_to_here))
			 same => n(jump_to_here),Goto(confbridge)
			 same => n,Goto(confbridge)
			 same => n(confbridge),ConfBridge(${EXTEN})
			</example>
			<para>This application sets the following channel variables:</para>
			<variablelist>
				<variable name="DIALEDTIME">
					<para>This is the time from dialing a channel until when it is disconnected.</para>
				</variable>
				<variable name="DIALEDTIME_MS">
					<para>This is the milliseconds version of the DIALEDTIME variable.</para>
				</variable>
				<variable name="ANSWEREDTIME">
					<para>This is the amount of time for actual call.</para>
				</variable>
				<variable name="ANSWEREDTIME_MS">
					<para>This is the milliseconds version of the ANSWEREDTIME variable.</para>
				</variable>
				<variable name="RINGTIME">
					<para>This is the time from creating the channel to the first RINGING event received. Empty if there was no ring.</para>
				</variable>
				<variable name="RINGTIME_MS">
					<para>This is the milliseconds version of the RINGTIME variable.</para>
				</variable>
				<variable name="PROGRESSTIME">
					<para>This is the time from creating the channel to the first PROGRESS event received. Empty if there was no such event.</para>
				</variable>
				<variable name="PROGRESSTIME_MS">
					<para>This is the milliseconds version of the PROGRESSTIME variable.</para>
				</variable>
				<variable name="DIALEDPEERNAME">
					<para>The name of the outbound channel that answered the call.</para>
				</variable>
				<variable name="DIALEDPEERNUMBER">
					<para>The number that was dialed for the answered outbound channel.</para>
				</variable>
				<variable name="FORWARDERNAME">
					<para>If a call forward occurred, the name of the forwarded channel.</para>
				</variable>
				<variable name="DIALSTATUS">
					<para>This is the status of the call</para>
					<value name="CHANUNAVAIL">
						Either the dialed peer exists but is not currently reachable, e.g.
						endpoint is not registered, or an attempt was made to call a
						nonexistent location, e.g. nonexistent DNS hostname.
					</value>
					<value name="CONGESTION">
						Channel or switching congestion occured when routing the call.
						This can occur if there is a slow or no response from the remote end.
					</value>
					<value name="NOANSWER">
						Called party did not answer.
					</value>
					<value name="BUSY">
						The called party was busy or indicated a busy status.
						Note that some SIP devices will respond with 486 Busy if their Do Not Disturb
						modes are active. In this case, you can use DEVICE_STATUS to check if the
						endpoint is actually in use, if needed.
					</value>
					<value name="ANSWER">
						The call was answered.
						Any other result implicitly indicates the call was not answered.
					</value>
					<value name="CANCEL">
						Dial was cancelled before call was answered or reached some other terminating event.
					</value>
					<value name="DONTCALL">
						For the Privacy and Screening Modes.
						Will be set if the called party chooses to send the calling party to the 'Go Away' script.
					</value>
					<value name="TORTURE">
						For the Privacy and Screening Modes.
						Will be set if the called party chooses to send the calling party to the 'torture' script.
					</value>
					<value name="INVALIDARGS">
						Dial failed due to invalid syntax.
					</value>
				</variable>
			</variablelist>
		</description>
		<see-also>
			<ref type="application">RetryDial</ref>
			<ref type="application">SendDTMF</ref>
			<ref type="application">Gosub</ref>
		</see-also>
	</application>
	<application name="RetryDial" language="en_US">
		<since>
			<version>1.2.0</version>
		</since>
		<synopsis>
			Place a call, retrying on failure allowing an optional exit extension.
		</synopsis>
		<syntax>
			<parameter name="announce" required="true">
				<para>Filename of sound that will be played when no channel can be reached</para>
			</parameter>
			<parameter name="sleep" required="true">
				<para>Number of seconds to wait after a dial attempt failed before a new attempt is made</para>
			</parameter>
			<parameter name="retries" required="true">
				<para>Number of retries</para>
				<para>When this is reached flow will continue at the next priority in the dialplan</para>
			</parameter>
			<parameter name="dialargs" required="true">
				<para>Same format as arguments provided to the Dial application</para>
			</parameter>
		</syntax>
		<description>
			<para>This application will attempt to place a call using the normal Dial application.
			If no channel can be reached, the <replaceable>announce</replaceable> file will be played.
			Then, it will wait <replaceable>sleep</replaceable> number of seconds before retrying the call.
			After <replaceable>retries</replaceable> number of attempts, the calling channel will continue at the next priority in the dialplan.
			If the <replaceable>retries</replaceable> setting is set to 0, this application will retry endlessly.
			While waiting to retry a call, a 1 digit extension may be dialed. If that
			extension exists in either the context defined in <variable>EXITCONTEXT</variable> or the current
			one, The call will jump to that extension immediately.
			The <replaceable>dialargs</replaceable> are specified in the same format that arguments are provided
			to the Dial application.</para>
		</description>
		<see-also>
			<ref type="application">Dial</ref>
		</see-also>
	</application>
 ***/

static const char app[] = "Dial";
static const char rapp[] = "RetryDial";

enum {
	OPT_ANNOUNCE =          (1 << 0),
	OPT_RESETCDR =          (1 << 1),
	OPT_DTMF_EXIT =         (1 << 2),
	OPT_SENDDTMF =          (1 << 3),
	OPT_FORCECLID =         (1 << 4),
	OPT_GO_ON =             (1 << 5),
	OPT_CALLEE_HANGUP =     (1 << 6),
	OPT_CALLER_HANGUP =     (1 << 7),
	OPT_ORIGINAL_CLID =     (1 << 8),
	OPT_DURATION_LIMIT =    (1 << 9),
	OPT_MUSICBACK =         (1 << 10),
	OPT_SCREEN_NOINTRO =    (1 << 12),
	OPT_SCREEN_NOCALLERID = (1 << 13),
	OPT_IGNORE_CONNECTEDLINE = (1 << 14),
	OPT_SCREENING =         (1 << 15),
	OPT_PRIVACY =           (1 << 16),
	OPT_RINGBACK =          (1 << 17),
	OPT_DURATION_STOP =     (1 << 18),
	OPT_CALLEE_TRANSFER =   (1 << 19),
	OPT_CALLER_TRANSFER =   (1 << 20),
	OPT_CALLEE_MONITOR =    (1 << 21),
	OPT_CALLER_MONITOR =    (1 << 22),
	OPT_GOTO =              (1 << 23),
	OPT_OPERMODE =          (1 << 24),
	OPT_CALLEE_PARK =       (1 << 25),
	OPT_CALLER_PARK =       (1 << 26),
	OPT_IGNORE_FORWARDING = (1 << 27),
	OPT_CALLEE_GOSUB =      (1 << 28),
	OPT_CALLEE_MIXMONITOR = (1 << 29),
	OPT_CALLER_MIXMONITOR = (1 << 30),
};

/* flags are now 64 bits, so keep it up! */
#define DIAL_STILLGOING      (1LLU << 31)
#define DIAL_NOFORWARDHTML   (1LLU << 32)
#define DIAL_CALLERID_ABSENT (1LLU << 33) /* TRUE if caller id is not available for connected line. */
#define OPT_CANCEL_ELSEWHERE (1LLU << 34)
#define OPT_PEER_H           (1LLU << 35)
#define OPT_CALLEE_GO_ON     (1LLU << 36)
#define OPT_CANCEL_TIMEOUT   (1LLU << 37)
#define OPT_FORCE_CID_TAG    (1LLU << 38)
#define OPT_FORCE_CID_PRES   (1LLU << 39)
#define OPT_CALLER_ANSWER    (1LLU << 40)
#define OPT_PREDIAL_CALLEE   (1LLU << 41)
#define OPT_PREDIAL_CALLER   (1LLU << 42)
#define OPT_RING_WITH_EARLY_MEDIA (1LLU << 43)
#define OPT_HANGUPCAUSE      (1LLU << 44)
#define OPT_HEARPULSING      (1LLU << 45)
#define OPT_TOPOLOGY_PRESERVE (1LLU << 46)

enum {
	OPT_ARG_ANNOUNCE = 0,
	OPT_ARG_SENDDTMF,
	OPT_ARG_GOTO,
	OPT_ARG_DURATION_LIMIT,
	OPT_ARG_MUSICBACK,
	OPT_ARG_RINGBACK,
	OPT_ARG_CALLEE_GOSUB,
	OPT_ARG_CALLEE_GO_ON,
	OPT_ARG_PRIVACY,
	OPT_ARG_DURATION_STOP,
	OPT_ARG_OPERMODE,
	OPT_ARG_SCREEN_NOINTRO,
	OPT_ARG_ORIGINAL_CLID,
	OPT_ARG_FORCECLID,
	OPT_ARG_FORCE_CID_TAG,
	OPT_ARG_FORCE_CID_PRES,
	OPT_ARG_PREDIAL_CALLEE,
	OPT_ARG_PREDIAL_CALLER,
	OPT_ARG_HANGUPCAUSE,
	/* note: this entry _MUST_ be the last one in the enum */
	OPT_ARG_ARRAY_SIZE
};

AST_APP_OPTIONS(dial_exec_options, BEGIN_OPTIONS
	AST_APP_OPTION_ARG('A', OPT_ANNOUNCE, OPT_ARG_ANNOUNCE),
	AST_APP_OPTION('a', OPT_CALLER_ANSWER),
	AST_APP_OPTION_ARG('b', OPT_PREDIAL_CALLEE, OPT_ARG_PREDIAL_CALLEE),
	AST_APP_OPTION_ARG('B', OPT_PREDIAL_CALLER, OPT_ARG_PREDIAL_CALLER),
	AST_APP_OPTION('C', OPT_RESETCDR),
	AST_APP_OPTION('c', OPT_CANCEL_ELSEWHERE),
	AST_APP_OPTION('d', OPT_DTMF_EXIT),
	AST_APP_OPTION_ARG('D', OPT_SENDDTMF, OPT_ARG_SENDDTMF),
	AST_APP_OPTION('E', OPT_HEARPULSING),
	AST_APP_OPTION('e', OPT_PEER_H),
	AST_APP_OPTION_ARG('f', OPT_FORCECLID, OPT_ARG_FORCECLID),
	AST_APP_OPTION_ARG('F', OPT_CALLEE_GO_ON, OPT_ARG_CALLEE_GO_ON),
	AST_APP_OPTION('g', OPT_GO_ON),
	AST_APP_OPTION_ARG('G', OPT_GOTO, OPT_ARG_GOTO),
	AST_APP_OPTION('h', OPT_CALLEE_HANGUP),
	AST_APP_OPTION('H', OPT_CALLER_HANGUP),
	AST_APP_OPTION('i', OPT_IGNORE_FORWARDING),
	AST_APP_OPTION('I', OPT_IGNORE_CONNECTEDLINE),
	AST_APP_OPTION('j', OPT_TOPOLOGY_PRESERVE),
	AST_APP_OPTION('k', OPT_CALLEE_PARK),
	AST_APP_OPTION('K', OPT_CALLER_PARK),
	AST_APP_OPTION_ARG('L', OPT_DURATION_LIMIT, OPT_ARG_DURATION_LIMIT),
	AST_APP_OPTION_ARG('m', OPT_MUSICBACK, OPT_ARG_MUSICBACK),
	AST_APP_OPTION_ARG('n', OPT_SCREEN_NOINTRO, OPT_ARG_SCREEN_NOINTRO),
	AST_APP_OPTION('N', OPT_SCREEN_NOCALLERID),
	AST_APP_OPTION_ARG('o', OPT_ORIGINAL_CLID, OPT_ARG_ORIGINAL_CLID),
	AST_APP_OPTION_ARG('O', OPT_OPERMODE, OPT_ARG_OPERMODE),
	AST_APP_OPTION('p', OPT_SCREENING),
	AST_APP_OPTION_ARG('P', OPT_PRIVACY, OPT_ARG_PRIVACY),
	AST_APP_OPTION_ARG('Q', OPT_HANGUPCAUSE, OPT_ARG_HANGUPCAUSE),
	AST_APP_OPTION_ARG('r', OPT_RINGBACK, OPT_ARG_RINGBACK),
	AST_APP_OPTION('R', OPT_RING_WITH_EARLY_MEDIA),
	AST_APP_OPTION_ARG('S', OPT_DURATION_STOP, OPT_ARG_DURATION_STOP),
	AST_APP_OPTION_ARG('s', OPT_FORCE_CID_TAG, OPT_ARG_FORCE_CID_TAG),
	AST_APP_OPTION('t', OPT_CALLEE_TRANSFER),
	AST_APP_OPTION('T', OPT_CALLER_TRANSFER),
	AST_APP_OPTION_ARG('u', OPT_FORCE_CID_PRES, OPT_ARG_FORCE_CID_PRES),
	AST_APP_OPTION_ARG('U', OPT_CALLEE_GOSUB, OPT_ARG_CALLEE_GOSUB),
	AST_APP_OPTION('w', OPT_CALLEE_MONITOR),
	AST_APP_OPTION('W', OPT_CALLER_MONITOR),
	AST_APP_OPTION('x', OPT_CALLEE_MIXMONITOR),
	AST_APP_OPTION('X', OPT_CALLER_MIXMONITOR),
	AST_APP_OPTION('z', OPT_CANCEL_TIMEOUT),
END_OPTIONS );

#define CAN_EARLY_BRIDGE(flags,chan,peer) (!ast_test_flag64(flags, OPT_CALLEE_HANGUP | \
	OPT_CALLER_HANGUP | OPT_CALLEE_TRANSFER | OPT_CALLER_TRANSFER | \
	OPT_CALLEE_MONITOR | OPT_CALLER_MONITOR | OPT_CALLEE_PARK |  \
	OPT_CALLER_PARK | OPT_ANNOUNCE | OPT_CALLEE_GOSUB) && \
	!ast_channel_audiohooks(chan) && !ast_channel_audiohooks(peer) && \
	ast_framehook_list_is_empty(ast_channel_framehooks(chan)) && ast_framehook_list_is_empty(ast_channel_framehooks(peer)))

/*
 * The list of active channels
 */
struct chanlist {
	AST_LIST_ENTRY(chanlist) node;
	struct ast_channel *chan;
	/*! Channel interface dialing string (is tech/number).  (Stored in stuff[]) */
	const char *interface;
	/*! Channel technology name.  (Stored in stuff[]) */
	const char *tech;
	/*! Channel device addressing.  (Stored in stuff[]) */
	const char *number;
	/*! Original channel name.  Must be freed.  Could be NULL if allocation failed. */
	char *orig_chan_name;
	uint64_t flags;
	/*! Saved connected party info from an AST_CONTROL_CONNECTED_LINE. */
	struct ast_party_connected_line connected;
	/*! TRUE if an AST_CONTROL_CONNECTED_LINE update was saved to the connected element. */
	unsigned int pending_connected_update:1;
	struct ast_aoc_decoded *aoc_s_rate_list;
	/*! The interface, tech, and number strings are stuffed here. */
	char stuff[0];
};

AST_LIST_HEAD_NOLOCK(dial_head, chanlist);

static void topology_ds_destroy(void *data) {
	struct ast_stream_topology *top = data;
	ast_stream_topology_free(top);
}

static const struct ast_datastore_info topology_ds_info = {
	.type = "app_dial_topology_preserve",
	.destroy = topology_ds_destroy,
};

static int detect_disconnect(struct ast_channel *chan, char code, struct ast_str **featurecode);

static void chanlist_free(struct chanlist *outgoing)
{
	ast_party_connected_line_free(&outgoing->connected);
	ast_aoc_destroy_decoded(outgoing->aoc_s_rate_list);
	ast_free(outgoing->orig_chan_name);
	ast_free(outgoing);
}

static void hanguptree(struct dial_head *out_chans, struct ast_channel *exception, int hangupcause)
{
	/* Hang up a tree of stuff */
	struct chanlist *outgoing;

	while ((outgoing = AST_LIST_REMOVE_HEAD(out_chans, node))) {
		/* Hangup any existing lines we have open */
		if (outgoing->chan && (outgoing->chan != exception)) {
			if (hangupcause >= 0) {
				/* This is for the channel drivers */
				ast_channel_hangupcause_set(outgoing->chan, hangupcause);
			}
			ast_hangup(outgoing->chan);
		}
		chanlist_free(outgoing);
	}
}

#define AST_MAX_WATCHERS 256

/*
 * argument to handle_cause() and other functions.
 */
struct cause_args {
	struct ast_channel *chan;
	int busy;
	int congestion;
	int nochan;
};

static void handle_cause(int cause, struct cause_args *num)
{
	switch(cause) {
	case AST_CAUSE_BUSY:
		num->busy++;
		break;
	case AST_CAUSE_CONGESTION:
		num->congestion++;
		break;
	case AST_CAUSE_NO_ROUTE_DESTINATION:
	case AST_CAUSE_UNREGISTERED:
		num->nochan++;
		break;
	case AST_CAUSE_NO_ANSWER:
	case AST_CAUSE_NORMAL_CLEARING:
		break;
	default:
		num->nochan++;
		break;
	}
}

static int onedigit_goto(struct ast_channel *chan, const char *context, char exten, int pri)
{
	char rexten[2] = { exten, '\0' };

	if (context) {
		if (!ast_goto_if_exists(chan, context, rexten, pri))
			return 1;
	} else {
		if (!ast_goto_if_exists(chan, ast_channel_context(chan), rexten, pri))
			return 1;
	}
	return 0;
}

/* do not call with chan lock held */
static const char *get_cid_name(char *name, int namelen, struct ast_channel *chan)
{
	const char *context;
	const char *exten;

	ast_channel_lock(chan);
	context = ast_strdupa(ast_channel_context(chan));
	exten = ast_strdupa(ast_channel_exten(chan));
	ast_channel_unlock(chan);

	return ast_get_hint(NULL, 0, name, namelen, chan, context, exten) ? name : "";
}

/*!
 * helper function for wait_for_answer()
 *
 * \param o Outgoing call channel list.
 * \param num Incoming call channel cause accumulation
 * \param peerflags Dial option flags
 * \param single TRUE if there is only one outgoing call.
 * \param caller_entertained TRUE if the caller is being entertained by MOH or ringback.
 * \param to Remaining call timeout time.
 * \param forced_clid OPT_FORCECLID caller id to send
 * \param stored_clid Caller id representing the called party if needed
 *
 * XXX this code is highly suspicious, as it essentially overwrites
 * the outgoing channel without properly deleting it.
 *
 * \todo eventually this function should be integrated into and replaced by ast_call_forward()
 */
static void do_forward(struct chanlist *o, struct cause_args *num,
	struct ast_flags64 *peerflags, int single, int caller_entertained, int *to,
	struct ast_party_id *forced_clid, struct ast_party_id *stored_clid)
{
	char tmpchan[256];
	char forwarder[AST_CHANNEL_NAME];
	struct ast_channel *original = o->chan;
	struct ast_channel *c = o->chan; /* the winner */
	struct ast_channel *in = num->chan; /* the input channel */
	char *stuff;
	char *tech;
	int cause;
	struct ast_party_caller caller;

	ast_copy_string(forwarder, ast_channel_name(c), sizeof(forwarder));
	ast_copy_string(tmpchan, ast_channel_call_forward(c), sizeof(tmpchan));
	if ((stuff = strchr(tmpchan, '/'))) {
		*stuff++ = '\0';
		tech = tmpchan;
	} else {
		const char *forward_context;
		ast_channel_lock(c);
		forward_context = pbx_builtin_getvar_helper(c, "FORWARD_CONTEXT");
		if (ast_strlen_zero(forward_context)) {
			forward_context = NULL;
		}
		snprintf(tmpchan, sizeof(tmpchan), "%s@%s", ast_channel_call_forward(c), forward_context ? forward_context : ast_channel_context(c));
		ast_channel_unlock(c);
		stuff = tmpchan;
		tech = "Local";
	}
	if (!strcasecmp(tech, "Local")) {
		/*
		 * Drop the connected line update block for local channels since
		 * this is going to run dialplan and the user can change his
		 * mind about what connected line information he wants to send.
		 */
		ast_clear_flag64(o, OPT_IGNORE_CONNECTEDLINE);
	}

	/* Before processing channel, go ahead and check for forwarding */
	ast_verb(3, "Now forwarding %s to '%s/%s' (thanks to %s)\n", ast_channel_name(in), tech, stuff, ast_channel_name(c));
	/* If we have been told to ignore forwards, just set this channel to null and continue processing extensions normally */
	if (ast_test_flag64(peerflags, OPT_IGNORE_FORWARDING)) {
		ast_verb(3, "Forwarding %s to '%s/%s' prevented.\n", ast_channel_name(in), tech, stuff);
		ast_channel_publish_dial_forward(in, original, NULL, NULL, "CANCEL",
			ast_channel_call_forward(original));
		c = o->chan = NULL;
		cause = AST_CAUSE_BUSY;
	} else {
		struct ast_stream_topology *topology;

		ast_channel_lock(in);
		topology = ast_stream_topology_clone(ast_channel_get_stream_topology(in));
		ast_channel_unlock(in);

		/* Setup parameters */
		c = o->chan = ast_request_with_stream_topology(tech, topology, NULL, in, stuff, &cause);

		ast_stream_topology_free(topology);

		if (c) {
			if (single && !caller_entertained) {
				ast_channel_make_compatible(in, o->chan);
			}
			ast_channel_lock_both(in, o->chan);
			ast_channel_inherit_variables(in, o->chan);
			ast_channel_datastore_inherit(in, o->chan);
			pbx_builtin_setvar_helper(o->chan, "FORWARDERNAME", forwarder);
			ast_max_forwards_decrement(o->chan);
			ast_channel_unlock(in);
			ast_channel_unlock(o->chan);
			/* When a call is forwarded, we don't want to track new interfaces
			 * dialed for CC purposes. Setting the done flag will ensure that
			 * any Dial operations that happen later won't record CC interfaces.
			 */
			ast_ignore_cc(o->chan);
			ast_verb(3, "Not accepting call completion offers from call-forward recipient %s\n",
				ast_channel_name(o->chan));
		} else
			ast_log(LOG_NOTICE,
				"Forwarding failed to create channel to dial '%s/%s' (cause = %d)\n",
				tech, stuff, cause);
	}
	if (!c) {
		ast_channel_publish_dial(in, original, stuff, "BUSY");
		ast_clear_flag64(o, DIAL_STILLGOING);
		handle_cause(cause, num);
		ast_hangup(original);
	} else {
		ast_channel_lock_both(c, original);
		ast_party_redirecting_copy(ast_channel_redirecting(c),
			ast_channel_redirecting(original));
		ast_channel_unlock(c);
		ast_channel_unlock(original);

		ast_channel_lock_both(c, in);

		if (single && !caller_entertained && CAN_EARLY_BRIDGE(peerflags, c, in)) {
			ast_rtp_instance_early_bridge_make_compatible(c, in);
		}

		if (!ast_channel_redirecting(c)->from.number.valid
			|| ast_strlen_zero(ast_channel_redirecting(c)->from.number.str)) {
			/*
			 * The call was not previously redirected so it is
			 * now redirected from this number.
			 */
			ast_party_number_free(&ast_channel_redirecting(c)->from.number);
			ast_party_number_init(&ast_channel_redirecting(c)->from.number);
			ast_channel_redirecting(c)->from.number.valid = 1;
			ast_channel_redirecting(c)->from.number.str =
				ast_strdup(ast_channel_exten(in));
		}

		ast_channel_dialed(c)->transit_network_select = ast_channel_dialed(in)->transit_network_select;

		/* Determine CallerID to store in outgoing channel. */
		ast_party_caller_set_init(&caller, ast_channel_caller(c));
		if (ast_test_flag64(peerflags, OPT_ORIGINAL_CLID)) {
			caller.id = *stored_clid;
			ast_channel_set_caller_event(c, &caller, NULL);
			ast_set_flag64(o, DIAL_CALLERID_ABSENT);
		} else if (ast_strlen_zero(S_COR(ast_channel_caller(c)->id.number.valid,
			ast_channel_caller(c)->id.number.str, NULL))) {
			/*
			 * The new channel has no preset CallerID number by the channel
			 * driver.  Use the dialplan extension and hint name.
			 */
			caller.id = *stored_clid;
			ast_channel_set_caller_event(c, &caller, NULL);
			ast_set_flag64(o, DIAL_CALLERID_ABSENT);
		} else {
			ast_clear_flag64(o, DIAL_CALLERID_ABSENT);
		}

		/* Determine CallerID for outgoing channel to send. */
		if (ast_test_flag64(o, OPT_FORCECLID)) {
			struct ast_party_connected_line connected;

			ast_party_connected_line_init(&connected);
			connected.id = *forced_clid;
			ast_party_connected_line_copy(ast_channel_connected(c), &connected);
		} else {
			ast_connected_line_copy_from_caller(ast_channel_connected(c), ast_channel_caller(in));
		}

		ast_channel_req_accountcodes(c, in, AST_CHANNEL_REQUESTOR_BRIDGE_PEER);

		ast_channel_appl_set(c, "AppDial");
		ast_channel_data_set(c, "(Outgoing Line)");
		ast_channel_publish_snapshot(c);

		ast_channel_unlock(in);
		if (single && !ast_test_flag64(o, OPT_IGNORE_CONNECTEDLINE)) {
			struct ast_party_redirecting redirecting;

			/*
			 * Redirecting updates to the caller make sense only on single
			 * calls.
			 *
			 * Need to re-evalute if unlocking is still required here as macro is gone
			 */
			ast_party_redirecting_init(&redirecting);
			ast_party_redirecting_copy(&redirecting, ast_channel_redirecting(c));
			ast_channel_unlock(c);
			if (ast_channel_redirecting_sub(c, in, &redirecting, 0)) {
				ast_channel_update_redirecting(in, &redirecting, NULL);
			}
			ast_party_redirecting_free(&redirecting);
		} else {
			ast_channel_unlock(c);
		}

		if (ast_test_flag64(peerflags, OPT_CANCEL_TIMEOUT)) {
			*to = -1;
		}

		if (ast_call(c, stuff, 0)) {
			ast_log(LOG_NOTICE, "Forwarding failed to dial '%s/%s'\n",
				tech, stuff);
			ast_channel_publish_dial(in, original, stuff, "CONGESTION");
			ast_clear_flag64(o, DIAL_STILLGOING);
			ast_hangup(original);
			ast_hangup(c);
			c = o->chan = NULL;
			num->nochan++;
		} else {
			ast_channel_publish_dial_forward(in, original, c, NULL, "CANCEL",
				ast_channel_call_forward(original));

			ast_channel_publish_dial(in, c, stuff, NULL);

			/* Hangup the original channel now, in case we needed it */
			ast_hangup(original);
		}
		if (single && !caller_entertained) {
			ast_indicate(in, -1);
		}
	}
}

/* argument used for some functions. */
struct privacy_args {
	int sentringing;
	int privdb_val;
	char privcid[256];
	char privintro[1024];
	char status[256];
	int canceled;
};

static void publish_dial_end_event(struct ast_channel *in, struct dial_head *out_chans, struct ast_channel *exception, const char *status)
{
	struct chanlist *outgoing;
	AST_LIST_TRAVERSE(out_chans, outgoing, node) {
		if (!outgoing->chan || outgoing->chan == exception) {
			continue;
		}
		ast_channel_publish_dial(in, outgoing->chan, NULL, status);
	}
}

/*!
 * \internal
 * \brief Update connected line on chan from peer.
 * \since 13.6.0
 *
 * \param chan Channel to get connected line updated.
 * \param peer Channel providing connected line information.
 * \param is_caller Non-zero if chan is the calling channel.
 */
static void update_connected_line_from_peer(struct ast_channel *chan, struct ast_channel *peer, int is_caller)
{
	struct ast_party_connected_line connected_caller;

	ast_party_connected_line_init(&connected_caller);

	ast_channel_lock(peer);
	ast_connected_line_copy_from_caller(&connected_caller, ast_channel_caller(peer));
	ast_channel_unlock(peer);
	connected_caller.source = AST_CONNECTED_LINE_UPDATE_SOURCE_ANSWER;
	if (ast_channel_connected_line_sub(peer, chan, &connected_caller, 0)) {
		ast_channel_update_connected_line(chan, &connected_caller, NULL);
	}
	ast_party_connected_line_free(&connected_caller);
}

/*!
 * \internal
 * \pre chan is locked
 */
static void set_duration_var(struct ast_channel *chan, const char *var_base, int64_t duration)
{
	char buf[32];
	char full_var_name[128];

	snprintf(buf, sizeof(buf), "%" PRId64, duration / 1000);
	pbx_builtin_setvar_helper(chan, var_base, buf);

	snprintf(full_var_name, sizeof(full_var_name), "%s_MS", var_base);
	snprintf(buf, sizeof(buf), "%" PRId64, duration);
	pbx_builtin_setvar_helper(chan, full_var_name, buf);
}

static struct ast_channel *wait_for_answer(struct ast_channel *in,
	struct dial_head *out_chans, int *to_answer, int *to_progress, struct ast_flags64 *peerflags,
	char *opt_args[],
	struct privacy_args *pa,
	const struct cause_args *num_in, int *result, char *dtmf_progress,
	char *mf_progress, char *mf_wink,
	char *sf_progress, char *sf_wink,
	const int hearpulsing,
	const int ignore_cc,
	struct ast_party_id *forced_clid, struct ast_party_id *stored_clid,
	struct ast_bridge_config *config)
{
	struct cause_args num = *num_in;
	int prestart = num.busy + num.congestion + num.nochan;
	int orig_answer_to = *to_answer;
	int orig_progress_to = *to_progress;
	struct ast_channel *peer = NULL;
	struct chanlist *outgoing = AST_LIST_FIRST(out_chans);
	/* single is set if only one destination is enabled */
	int single = outgoing && !AST_LIST_NEXT(outgoing, node);
	int caller_entertained = outgoing
		&& ast_test_flag64(outgoing, OPT_MUSICBACK | OPT_RINGBACK);
	struct ast_str *featurecode = ast_str_alloca(AST_FEATURE_MAX_LEN + 1);
	int cc_recall_core_id;
	int is_cc_recall;
	int cc_frame_received = 0;
	int num_ringing = 0;
	int sent_ring = 0;
	int sent_progress = 0, sent_wink = 0;
	struct timeval start = ast_tvnow();
	SCOPE_ENTER(3, "%s\n", ast_channel_name(in));

	if (single) {
		/* Turn off hold music, etc */
		if (!caller_entertained) {
			ast_deactivate_generator(in);
			/* If we are calling a single channel, and not providing ringback or music, */
			/* then, make them compatible for in-band tone purpose */
			if (ast_channel_make_compatible(in, outgoing->chan) < 0) {
				/* If these channels can not be made compatible,
				 * there is no point in continuing.  The bridge
				 * will just fail if it gets that far.
				 */
				*to_answer = -1;
				strcpy(pa->status, "CONGESTION");
				ast_channel_publish_dial(in, outgoing->chan, NULL, pa->status);
				SCOPE_EXIT_RTN_VALUE(NULL, "%s: can't be made compat with %s\n",
					ast_channel_name(in), ast_channel_name(outgoing->chan));
			}
		}

		if (!ast_test_flag64(outgoing, OPT_IGNORE_CONNECTEDLINE)
			&& !ast_test_flag64(outgoing, DIAL_CALLERID_ABSENT)) {
			update_connected_line_from_peer(in, outgoing->chan, 1);
		}
	}

	is_cc_recall = ast_cc_is_recall(in, &cc_recall_core_id, NULL);

	while ((*to_answer = ast_remaining_ms(start, orig_answer_to)) && (*to_progress = ast_remaining_ms(start, orig_progress_to)) && !peer) {
		struct chanlist *o;
		int pos = 0; /* how many channels do we handle */
		int numlines = prestart;
		struct ast_channel *winner;
		struct ast_channel *watchers[AST_MAX_WATCHERS];

		watchers[pos++] = in;
		AST_LIST_TRAVERSE(out_chans, o, node) {
			/* Keep track of important channels */
			if (ast_test_flag64(o, DIAL_STILLGOING) && o->chan)
				watchers[pos++] = o->chan;
			numlines++;
		}
		if (pos == 1) { /* only the input channel is available */
			if (numlines == (num.busy + num.congestion + num.nochan)) {
				ast_verb(2, "Everyone is busy/congested at this time (%d:%d/%d/%d)\n", numlines, num.busy, num.congestion, num.nochan);
				if (num.busy)
					strcpy(pa->status, "BUSY");
				else if (num.congestion)
					strcpy(pa->status, "CONGESTION");
				else if (num.nochan)
					strcpy(pa->status, "CHANUNAVAIL");
			} else {
				ast_verb(3, "No one is available to answer at this time (%d:%d/%d/%d)\n", numlines, num.busy, num.congestion, num.nochan);
			}
			*to_answer = 0;
			if (is_cc_recall) {
				ast_cc_failed(cc_recall_core_id, "Everyone is busy/congested for the recall. How sad");
			}
			SCOPE_EXIT_RTN_VALUE(NULL, "%s: No outgoing channels available\n", ast_channel_name(in));
		}

		/* If progress timeout is active, use that if it's the shorter of the 2 timeouts. */
		winner = ast_waitfor_n(watchers, pos, *to_progress > 0 && (*to_answer < 0 || *to_progress < *to_answer) ? to_progress : to_answer);

		AST_LIST_TRAVERSE(out_chans, o, node) {
			int res = 0;
			struct ast_frame *f;
			struct ast_channel *c = o->chan;

			if (c == NULL)
				continue;
			if (ast_test_flag64(o, DIAL_STILLGOING) && ast_channel_state(c) == AST_STATE_UP) {
				if (!peer) {
					ast_verb(3, "%s answered %s\n", ast_channel_name(c), ast_channel_name(in));
					if (o->orig_chan_name
						&& strcmp(o->orig_chan_name, ast_channel_name(c))) {
						/*
						 * The channel name changed so we must generate COLP update.
						 * Likely because a call pickup channel masqueraded in.
						 */
						update_connected_line_from_peer(in, c, 1);
					} else if (!single && !ast_test_flag64(o, OPT_IGNORE_CONNECTEDLINE)) {
						if (o->pending_connected_update) {
							if (ast_channel_connected_line_sub(c, in, &o->connected, 0)) {
								ast_channel_update_connected_line(in, &o->connected, NULL);
							}
						} else if (!ast_test_flag64(o, DIAL_CALLERID_ABSENT)) {
							update_connected_line_from_peer(in, c, 1);
						}
					}
					if (o->aoc_s_rate_list) {
						size_t encoded_size;
						struct ast_aoc_encoded *encoded;
						if ((encoded = ast_aoc_encode(o->aoc_s_rate_list, &encoded_size, o->chan))) {
							ast_indicate_data(in, AST_CONTROL_AOC, encoded, encoded_size);
							ast_aoc_destroy_encoded(encoded);
						}
					}
					peer = c;
					publish_dial_end_event(in, out_chans, peer, "CANCEL");
					ast_copy_flags64(peerflags, o,
						OPT_CALLEE_TRANSFER | OPT_CALLER_TRANSFER |
						OPT_CALLEE_HANGUP | OPT_CALLER_HANGUP |
						OPT_CALLEE_MONITOR | OPT_CALLER_MONITOR |
						OPT_CALLEE_PARK | OPT_CALLER_PARK |
						OPT_CALLEE_MIXMONITOR | OPT_CALLER_MIXMONITOR |
						DIAL_NOFORWARDHTML);
					ast_channel_dialcontext_set(c, "");
					ast_channel_exten_set(c, "");
				}
				continue;
			}
			if (c != winner)
				continue;
			/* here, o->chan == c == winner */
			if (!ast_strlen_zero(ast_channel_call_forward(c))) {
				pa->sentringing = 0;
				if (!ignore_cc && (f = ast_read(c))) {
					if (f->frametype == AST_FRAME_CONTROL && f->subclass.integer == AST_CONTROL_CC) {
						/* This channel is forwarding the call, and is capable of CC, so
						 * be sure to add the new device interface to the list
						 */
						ast_handle_cc_control_frame(in, c, f->data.ptr);
					}
					ast_frfree(f);
				}

				if (o->pending_connected_update) {
					/*
					 * Re-seed the chanlist's connected line information with
					 * previously acquired connected line info from the incoming
					 * channel.  The previously acquired connected line info could
					 * have been set through the CONNECTED_LINE dialplan function.
					 */
					o->pending_connected_update = 0;
					ast_channel_lock(in);
					ast_party_connected_line_copy(&o->connected, ast_channel_connected(in));
					ast_channel_unlock(in);
				}

				do_forward(o, &num, peerflags, single, caller_entertained, &orig_answer_to,
					forced_clid, stored_clid);

				if (o->chan) {
					ast_free(o->orig_chan_name);
					o->orig_chan_name = ast_strdup(ast_channel_name(o->chan));
					if (single
						&& !ast_test_flag64(o, OPT_IGNORE_CONNECTEDLINE)
						&& !ast_test_flag64(o, DIAL_CALLERID_ABSENT)) {
						update_connected_line_from_peer(in, o->chan, 1);
					}
				}
				continue;
			}
			f = ast_read(winner);
			if (!f) {
				ast_channel_hangupcause_set(in, ast_channel_hangupcause(c));
				ast_channel_publish_dial(in, c, NULL, ast_hangup_cause_to_dial_status(ast_channel_hangupcause(c)));
				ast_hangup(c);
				c = o->chan = NULL;
				ast_clear_flag64(o, DIAL_STILLGOING);
				handle_cause(ast_channel_hangupcause(in), &num);
				continue;
			}
			switch (f->frametype) {
			case AST_FRAME_CONTROL:
				switch (f->subclass.integer) {
				case AST_CONTROL_ANSWER:
					/* This is our guy if someone answered. */
					if (!peer) {
						ast_trace(-1, "%s answered %s\n", ast_channel_name(c), ast_channel_name(in));
						ast_verb(3, "%s answered %s\n", ast_channel_name(c), ast_channel_name(in));
						if (o->orig_chan_name
							&& strcmp(o->orig_chan_name, ast_channel_name(c))) {
							/*
							 * The channel name changed so we must generate COLP update.
							 * Likely because a call pickup channel masqueraded in.
							 */
							update_connected_line_from_peer(in, c, 1);
						} else if (!single && !ast_test_flag64(o, OPT_IGNORE_CONNECTEDLINE)) {
							if (o->pending_connected_update) {
								if (ast_channel_connected_line_sub(c, in, &o->connected, 0)) {
									ast_channel_update_connected_line(in, &o->connected, NULL);
								}
							} else if (!ast_test_flag64(o, DIAL_CALLERID_ABSENT)) {
								update_connected_line_from_peer(in, c, 1);
							}
						}
						if (o->aoc_s_rate_list) {
							size_t encoded_size;
							struct ast_aoc_encoded *encoded;
							if ((encoded = ast_aoc_encode(o->aoc_s_rate_list, &encoded_size, o->chan))) {
								ast_indicate_data(in, AST_CONTROL_AOC, encoded, encoded_size);
								ast_aoc_destroy_encoded(encoded);
							}
						}
						peer = c;
						/* Answer can optionally include a topology */
						if (f->subclass.topology) {
							/*
							 * We need to bump the refcount on the topology to prevent it
							 * from being cleaned up when the frame is cleaned up.
							 */
							config->answer_topology = ao2_bump(f->subclass.topology);
							ast_trace(-1, "%s Found topology in frame: %p %p %s\n",
								ast_channel_name(peer), f, config->answer_topology,
								ast_str_tmp(256, ast_stream_topology_to_str(config->answer_topology, &STR_TMP)));
						}

						/* Inform everyone else that they've been canceled.
						 * The dial end event for the peer will be sent out after
						 * other Dial options have been handled.
						 */
						publish_dial_end_event(in, out_chans, peer, "CANCEL");
						ast_copy_flags64(peerflags, o,
							OPT_CALLEE_TRANSFER | OPT_CALLER_TRANSFER |
							OPT_CALLEE_HANGUP | OPT_CALLER_HANGUP |
							OPT_CALLEE_MONITOR | OPT_CALLER_MONITOR |
							OPT_CALLEE_PARK | OPT_CALLER_PARK |
							OPT_CALLEE_MIXMONITOR | OPT_CALLER_MIXMONITOR |
							DIAL_NOFORWARDHTML);
						ast_channel_dialcontext_set(c, "");
						ast_channel_exten_set(c, "");
						if (CAN_EARLY_BRIDGE(peerflags, in, peer)) {
							/* Setup early bridge if appropriate */
							ast_channel_early_bridge(in, peer);
						}
					}
					/* If call has been answered, then the eventual hangup is likely to be normal hangup */
					ast_channel_hangupcause_set(in, AST_CAUSE_NORMAL_CLEARING);
					ast_channel_hangupcause_set(c, AST_CAUSE_NORMAL_CLEARING);
					break;
				case AST_CONTROL_BUSY:
					ast_verb(3, "%s is busy\n", ast_channel_name(c));
					ast_channel_hangupcause_set(in, ast_channel_hangupcause(c));
					ast_channel_publish_dial(in, c, NULL, "BUSY");
					ast_hangup(c);
					c = o->chan = NULL;
					ast_clear_flag64(o, DIAL_STILLGOING);
					handle_cause(AST_CAUSE_BUSY, &num);
					break;
				case AST_CONTROL_CONGESTION:
					ast_verb(3, "%s is circuit-busy\n", ast_channel_name(c));
					ast_channel_hangupcause_set(in, ast_channel_hangupcause(c));
					ast_channel_publish_dial(in, c, NULL, "CONGESTION");
					ast_hangup(c);
					c = o->chan = NULL;
					ast_clear_flag64(o, DIAL_STILLGOING);
					handle_cause(AST_CAUSE_CONGESTION, &num);
					break;
				case AST_CONTROL_RINGING:
					/* This is a tricky area to get right when using a native
					 * CC agent. The reason is that we do the best we can to send only a
					 * single ringing notification to the caller.
					 *
					 * Call completion complicates the logic used here. CCNR is typically
					 * offered during a ringing message. Let's say that party A calls
					 * parties B, C, and D. B and C do not support CC requests, but D
					 * does. If we were to receive a ringing notification from B before
					 * the others, then we would end up sending a ringing message to
					 * A with no CCNR offer present.
					 *
					 * The approach that we have taken is that if we receive a ringing
					 * response from a party and no CCNR offer is present, we need to
					 * wait. Specifically, we need to wait until either a) a called party
					 * offers CCNR in its ringing response or b) all called parties have
					 * responded in some way to our call and none offers CCNR.
					 *
					 * The drawback to this is that if one of the parties has a delayed
					 * response or, god forbid, one just plain doesn't respond to our
					 * outgoing call, then this will result in a significant delay between
					 * when the caller places the call and hears ringback.
					 *
					 * Note also that if CC is disabled for this call, then it is perfectly
					 * fine for ringing frames to get sent through.
					 */
					++num_ringing;
					*to_progress = -1;
					orig_progress_to = -1;
					if (ignore_cc || cc_frame_received || num_ringing == numlines) {
						ast_verb(3, "%s is ringing\n", ast_channel_name(c));
						/* Setup early media if appropriate */
						if (single && !caller_entertained
							&& CAN_EARLY_BRIDGE(peerflags, in, c)) {
							ast_channel_early_bridge(in, c);
						}
						if (!(pa->sentringing) && !ast_test_flag64(outgoing, OPT_MUSICBACK) && ast_strlen_zero(opt_args[OPT_ARG_RINGBACK])) {
							ast_indicate(in, AST_CONTROL_RINGING);
							pa->sentringing++;
						}
						if (!sent_ring) {
							struct timeval now, then;
							int64_t diff;

							now = ast_tvnow();

							ast_channel_lock(in);
							ast_channel_stage_snapshot(in);

							then = ast_channel_creationtime(c);
							diff = ast_tvzero(then) ? 0 : ast_tvdiff_ms(now, then);
							set_duration_var(in, "RINGTIME", diff);

							ast_channel_stage_snapshot_done(in);
							ast_channel_unlock(in);
							sent_ring = 1;
						}
					}
					ast_channel_publish_dial(in, c, NULL, "RINGING");
					break;
				case AST_CONTROL_PROGRESS:
					ast_verb(3, "%s is making progress passing it to %s\n", ast_channel_name(c), ast_channel_name(in));
					/* Setup early media if appropriate */
					if (single && !caller_entertained
						&& CAN_EARLY_BRIDGE(peerflags, in, c)) {
						ast_channel_early_bridge(in, c);
					}
					if (!ast_test_flag64(outgoing, OPT_RINGBACK)) {
						if (single || (!single && !pa->sentringing)) {
							ast_indicate(in, AST_CONTROL_PROGRESS);
						}
					}
					*to_progress = -1;
					orig_progress_to = -1;
					if (!sent_progress) {
						struct timeval now, then;
						int64_t diff;

						now = ast_tvnow();

						ast_channel_lock(in);
						ast_channel_stage_snapshot(in);

						then = ast_channel_creationtime(c);
						diff = ast_tvzero(then) ? 0 : ast_tvdiff_ms(now, then);
						set_duration_var(in, "PROGRESSTIME", diff);

						ast_channel_stage_snapshot_done(in);
						ast_channel_unlock(in);
						sent_progress = 1;

						if (!ast_strlen_zero(mf_progress)) {
							ast_verb(3,
								"Sending MF '%s' to %s as result of "
								"receiving a PROGRESS message.\n",
								mf_progress, hearpulsing ? "parties" : "called party");
							res |= ast_mf_stream(c, (hearpulsing ? NULL : in),
							(hearpulsing ? in : NULL), mf_progress, 50, 55, 120, 65, 0);
						}
						if (!ast_strlen_zero(sf_progress)) {
							ast_verb(3,
								"Sending SF '%s' to %s as result of "
								"receiving a PROGRESS message.\n",
								sf_progress, (hearpulsing ? "parties" : "called party"));
							res |= ast_sf_stream(c, (hearpulsing ? NULL : in),
							(hearpulsing ? in : NULL), sf_progress, 0, 0);
						}
						if (!ast_strlen_zero(dtmf_progress)) {
							ast_verb(3,
								"Sending DTMF '%s' to the called party as result of "
								"receiving a PROGRESS message.\n",
								dtmf_progress);
							res |= ast_dtmf_stream(c, in, dtmf_progress, 250, 0);
						}
						if (res) {
							ast_log(LOG_WARNING, "Called channel %s hung up post-progress before all digits could be sent\n", ast_channel_name(c));
							goto wait_over;
						}
					}
					ast_channel_publish_dial(in, c, NULL, "PROGRESS");
					break;
				case AST_CONTROL_WINK:
					ast_verb(3, "%s winked, passing it to %s\n", ast_channel_name(c), ast_channel_name(in));
					if (!sent_wink) {
						sent_wink = 1;
						if (!ast_strlen_zero(mf_wink)) {
							ast_verb(3,
								"Sending MF '%s' to %s as result of "
								"receiving a WINK message.\n",
								mf_wink, (hearpulsing ? "parties" : "called party"));
							res |= ast_mf_stream(c, (hearpulsing ? NULL : in),
							(hearpulsing ? in : NULL), mf_wink, 50, 55, 120, 65, 0);
						}
						if (!ast_strlen_zero(sf_wink)) {
							ast_verb(3,
								"Sending SF '%s' to %s as result of "
								"receiving a WINK message.\n",
								sf_wink, (hearpulsing ? "parties" : "called party"));
							res |= ast_sf_stream(c, (hearpulsing ? NULL : in),
							(hearpulsing ? in : NULL), sf_wink, 0, 0);
						}
						if (res) {
							ast_log(LOG_WARNING, "Called channel %s hung up post-wink before all digits could be sent\n", ast_channel_name(c));
							goto wait_over;
						}
					}
					ast_indicate(in, AST_CONTROL_WINK);
					break;
				case AST_CONTROL_VIDUPDATE:
				case AST_CONTROL_SRCUPDATE:
				case AST_CONTROL_SRCCHANGE:
					if (!single || caller_entertained) {
						break;
					}
					ast_verb(3, "%s requested media update control %d, passing it to %s\n",
						ast_channel_name(c), f->subclass.integer, ast_channel_name(in));
					ast_indicate(in, f->subclass.integer);
					break;
				case AST_CONTROL_CONNECTED_LINE:
					if (ast_test_flag64(o, OPT_IGNORE_CONNECTEDLINE)) {
						ast_verb(3, "Connected line update to %s prevented.\n", ast_channel_name(in));
						break;
					}
					if (!single) {
						struct ast_party_connected_line connected;

						ast_verb(3, "%s connected line has changed. Saving it until answer for %s\n",
							ast_channel_name(c), ast_channel_name(in));
						ast_party_connected_line_set_init(&connected, &o->connected);
						ast_connected_line_parse_data(f->data.ptr, f->datalen, &connected);
						ast_party_connected_line_set(&o->connected, &connected, NULL);
						ast_party_connected_line_free(&connected);
						o->pending_connected_update = 1;
						break;
					}
					if (ast_channel_connected_line_sub(c, in, f, 1)) {
						ast_indicate_data(in, AST_CONTROL_CONNECTED_LINE, f->data.ptr, f->datalen);
					}
					break;
				case AST_CONTROL_AOC:
					{
						struct ast_aoc_decoded *decoded = ast_aoc_decode(f->data.ptr, f->datalen, o->chan);
						if (decoded && (ast_aoc_get_msg_type(decoded) == AST_AOC_S)) {
							ast_aoc_destroy_decoded(o->aoc_s_rate_list);
							o->aoc_s_rate_list = decoded;
						} else {
							ast_aoc_destroy_decoded(decoded);
						}
					}
					break;
				case AST_CONTROL_REDIRECTING:
					if (!single) {
						/*
						 * Redirecting updates to the caller make sense only on single
						 * calls.
						 */
						break;
					}
					if (ast_test_flag64(o, OPT_IGNORE_CONNECTEDLINE)) {
						ast_verb(3, "Redirecting update to %s prevented.\n", ast_channel_name(in));
						break;
					}
					ast_verb(3, "%s redirecting info has changed, passing it to %s\n",
						ast_channel_name(c), ast_channel_name(in));
					if (ast_channel_redirecting_sub(c, in, f, 1)) {
						ast_indicate_data(in, AST_CONTROL_REDIRECTING, f->data.ptr, f->datalen);
					}
					pa->sentringing = 0;
					break;
				case AST_CONTROL_PROCEEDING:
					ast_verb(3, "%s is proceeding passing it to %s\n", ast_channel_name(c), ast_channel_name(in));
					if (single && !caller_entertained
						&& CAN_EARLY_BRIDGE(peerflags, in, c)) {
						ast_channel_early_bridge(in, c);
					}
					if (!ast_test_flag64(outgoing, OPT_RINGBACK))
						ast_indicate(in, AST_CONTROL_PROCEEDING);
					ast_channel_publish_dial(in, c, NULL, "PROCEEDING");
					break;
				case AST_CONTROL_HOLD:
					/* XXX this should be saved like AST_CONTROL_CONNECTED_LINE for !single || caller_entertained */
					ast_verb(3, "Call on %s placed on hold\n", ast_channel_name(c));
					ast_indicate_data(in, AST_CONTROL_HOLD, f->data.ptr, f->datalen);
					break;
				case AST_CONTROL_UNHOLD:
					/* XXX this should be saved like AST_CONTROL_CONNECTED_LINE for !single || caller_entertained */
					ast_verb(3, "Call on %s left from hold\n", ast_channel_name(c));
					ast_indicate(in, AST_CONTROL_UNHOLD);
					break;
				case AST_CONTROL_OFFHOOK:
				case AST_CONTROL_FLASH:
					/* Ignore going off hook and flash */
					break;
				case AST_CONTROL_CC:
					if (!ignore_cc) {
						ast_handle_cc_control_frame(in, c, f->data.ptr);
						cc_frame_received = 1;
					}
					break;
				case AST_CONTROL_PVT_CAUSE_CODE:
					ast_indicate_data(in, AST_CONTROL_PVT_CAUSE_CODE, f->data.ptr, f->datalen);
					break;
				case -1:
					if (single && !caller_entertained) {
						ast_verb(3, "%s stopped sounds\n", ast_channel_name(c));
						ast_indicate(in, -1);
						pa->sentringing = 0;
					}
					break;
				default:
					ast_debug(1, "Dunno what to do with control type %d\n", f->subclass.integer);
					break;
				}
				break;
			case AST_FRAME_VIDEO:
			case AST_FRAME_VOICE:
			case AST_FRAME_IMAGE:
			case AST_FRAME_DTMF_BEGIN:
			case AST_FRAME_DTMF_END:
				if (caller_entertained) {
					break;
				}
				*to_progress = -1;
				orig_progress_to = -1;
				/* Fall through */
			case AST_FRAME_TEXT:
				if (single && ast_write(in, f)) {
					ast_log(LOG_WARNING, "Unable to write frametype: %u\n",
						f->frametype);
				}
				break;
			case AST_FRAME_HTML:
				if (single && !ast_test_flag64(outgoing, DIAL_NOFORWARDHTML)
					&& ast_channel_sendhtml(in, f->subclass.integer, f->data.ptr, f->datalen) == -1) {
					ast_log(LOG_WARNING, "Unable to send URL\n");
				}
				break;
			default:
				break;
			}
			ast_frfree(f);
		} /* end for */
		if (winner == in) {
			struct ast_frame *f = ast_read(in);
#if 0
			if (f && (f->frametype != AST_FRAME_VOICE))
				printf("Frame type: %d, %d\n", f->frametype, f->subclass);
			else if (!f || (f->frametype != AST_FRAME_VOICE))
				printf("Hangup received on %s\n", in->name);
#endif
			if (!f || ((f->frametype == AST_FRAME_CONTROL) && (f->subclass.integer == AST_CONTROL_HANGUP))) {
				/* Got hung up */
				*to_answer = -1;
				strcpy(pa->status, "CANCEL");
				pa->canceled = 1;
				publish_dial_end_event(in, out_chans, NULL, pa->status);
				if (f) {
					if (f->data.uint32) {
						ast_channel_hangupcause_set(in, f->data.uint32);
					}
					ast_frfree(f);
				}
				if (is_cc_recall) {
					ast_cc_completed(in, "CC completed, although the caller hung up (cancelled)");
				}
				SCOPE_EXIT_RTN_VALUE(NULL, "%s: Caller hung up\n", ast_channel_name(in));
			}

			/* now f is guaranteed non-NULL */
			if (f->frametype == AST_FRAME_DTMF) {
				if (ast_test_flag64(peerflags, OPT_DTMF_EXIT)) {
					const char *context;
					ast_channel_lock(in);
					context = pbx_builtin_getvar_helper(in, "EXITCONTEXT");
					if (onedigit_goto(in, context, (char) f->subclass.integer, 1)) {
						ast_verb(3, "User hit %c to disconnect call.\n", f->subclass.integer);
						*to_answer = 0;
						*result = f->subclass.integer;
						strcpy(pa->status, "CANCEL");
						pa->canceled = 1;
						publish_dial_end_event(in, out_chans, NULL, pa->status);
						ast_frfree(f);
						ast_channel_unlock(in);
						if (is_cc_recall) {
							ast_cc_completed(in, "CC completed, but the caller used DTMF to exit");
						}
						SCOPE_EXIT_RTN_VALUE(NULL, "%s: Caller pressed %c to end call\n",
							ast_channel_name(in), f->subclass.integer);
					}
					ast_channel_unlock(in);
				}

				if (ast_test_flag64(peerflags, OPT_CALLER_HANGUP) &&
					detect_disconnect(in, f->subclass.integer, &featurecode)) {
					ast_verb(3, "User requested call disconnect.\n");
					*to_answer = 0;
					strcpy(pa->status, "CANCEL");
					pa->canceled = 1;
					publish_dial_end_event(in, out_chans, NULL, pa->status);
					ast_frfree(f);
					if (is_cc_recall) {
						ast_cc_completed(in, "CC completed, but the caller hung up with DTMF");
					}
					SCOPE_EXIT_RTN_VALUE(NULL, "%s: Caller requested disconnect\n",
						ast_channel_name(in));
				}
			}

			/* Send the frame from the in channel to all outgoing channels. */
			AST_LIST_TRAVERSE(out_chans, o, node) {
				if (!o->chan || !ast_test_flag64(o, DIAL_STILLGOING)) {
					/* This outgoing channel has died so don't send the frame to it. */
					continue;
				}
				switch (f->frametype) {
				case AST_FRAME_HTML:
					/* Forward HTML stuff */
					if (!ast_test_flag64(o, DIAL_NOFORWARDHTML)
						&& ast_channel_sendhtml(o->chan, f->subclass.integer, f->data.ptr, f->datalen) == -1) {
						ast_log(LOG_WARNING, "Unable to send URL\n");
					}
					break;
				case AST_FRAME_VIDEO:
				case AST_FRAME_VOICE:
				case AST_FRAME_IMAGE:
					if (!single || caller_entertained) {
						/*
						 * We are calling multiple parties or caller is being
						 * entertained and has thus not been made compatible.
						 * No need to check any other called parties.
						 */
						goto skip_frame;
					}
					/* Fall through */
				case AST_FRAME_TEXT:
				case AST_FRAME_DTMF_BEGIN:
				case AST_FRAME_DTMF_END:
					if (ast_write(o->chan, f)) {
						ast_log(LOG_WARNING, "Unable to forward frametype: %u\n",
							f->frametype);
					}
					break;
				case AST_FRAME_CONTROL:
					switch (f->subclass.integer) {
					case AST_CONTROL_HOLD:
						ast_verb(3, "Call on %s placed on hold\n", ast_channel_name(o->chan));
						ast_indicate_data(o->chan, AST_CONTROL_HOLD, f->data.ptr, f->datalen);
						break;
					case AST_CONTROL_UNHOLD:
						ast_verb(3, "Call on %s left from hold\n", ast_channel_name(o->chan));
						ast_indicate(o->chan, AST_CONTROL_UNHOLD);
						break;
					case AST_CONTROL_FLASH:
						ast_verb(3, "Hook flash on %s\n", ast_channel_name(o->chan));
						ast_indicate(o->chan, AST_CONTROL_FLASH);
						break;
					case AST_CONTROL_VIDUPDATE:
					case AST_CONTROL_SRCUPDATE:
					case AST_CONTROL_SRCCHANGE:
						if (!single || caller_entertained) {
							/*
							 * We are calling multiple parties or caller is being
							 * entertained and has thus not been made compatible.
							 * No need to check any other called parties.
							 */
							goto skip_frame;
						}
						ast_verb(3, "%s requested media update control %d, passing it to %s\n",
							ast_channel_name(in), f->subclass.integer, ast_channel_name(o->chan));
						ast_indicate(o->chan, f->subclass.integer);
						break;
					case AST_CONTROL_CONNECTED_LINE:
						if (ast_test_flag64(o, OPT_IGNORE_CONNECTEDLINE)) {
							ast_verb(3, "Connected line update to %s prevented.\n", ast_channel_name(o->chan));
							break;
						}
						if (ast_channel_connected_line_sub(in, o->chan, f, 1)) {
							ast_indicate_data(o->chan, f->subclass.integer, f->data.ptr, f->datalen);
						}
						break;
					case AST_CONTROL_REDIRECTING:
						if (ast_test_flag64(o, OPT_IGNORE_CONNECTEDLINE)) {
							ast_verb(3, "Redirecting update to %s prevented.\n", ast_channel_name(o->chan));
							break;
						}
						if (ast_channel_redirecting_sub(in, o->chan, f, 1)) {
							ast_indicate_data(o->chan, f->subclass.integer, f->data.ptr, f->datalen);
						}
						break;
					default:
						/* We are not going to do anything with this frame. */
						goto skip_frame;
					}
					break;
				default:
					/* We are not going to do anything with this frame. */
					goto skip_frame;
				}
			}
skip_frame:;
			ast_frfree(f);
		}
	}

wait_over:
	if (!*to_answer || ast_check_hangup(in)) {
		ast_verb(3, "Nobody picked up in %d ms\n", orig_answer_to);
		publish_dial_end_event(in, out_chans, NULL, "NOANSWER");
	} else if (!*to_progress) {
		ast_verb(3, "No early media received in %d ms\n", orig_progress_to);
		publish_dial_end_event(in, out_chans, NULL, "CHANUNAVAIL");
		strcpy(pa->status, "CHANUNAVAIL");
		*to_answer = 0; /* Reset to prevent hangup */
	}

	if (is_cc_recall) {
		ast_cc_completed(in, "Recall completed!");
	}
	SCOPE_EXIT_RTN_VALUE(peer, "%s: %s%s\n", ast_channel_name(in),
		peer ? "Answered by " : "No answer", peer ? ast_channel_name(peer) : "");
}

static int detect_disconnect(struct ast_channel *chan, char code, struct ast_str **featurecode)
{
	char disconnect_code[AST_FEATURE_MAX_LEN];
	int res;

	ast_str_append(featurecode, 1, "%c", code);

	res = ast_get_builtin_feature(chan, "disconnect", disconnect_code, sizeof(disconnect_code));
	if (res) {
		ast_str_reset(*featurecode);
		return 0;
	}

	if (strlen(disconnect_code) > ast_str_strlen(*featurecode)) {
		/* Could be a partial match, anyway */
		if (strncmp(disconnect_code, ast_str_buffer(*featurecode), ast_str_strlen(*featurecode))) {
			ast_str_reset(*featurecode);
		}
		return 0;
	}

	if (strcmp(disconnect_code, ast_str_buffer(*featurecode))) {
		ast_str_reset(*featurecode);
		return 0;
	}

	return 1;
}

/* returns true if there is a valid privacy reply */
static int valid_priv_reply(struct ast_flags64 *opts, int res)
{
	if (res < '1')
		return 0;
	if (ast_test_flag64(opts, OPT_PRIVACY) && res <= '5')
		return 1;
	if (ast_test_flag64(opts, OPT_SCREENING) && res <= '4')
		return 1;
	return 0;
}

static int do_privacy(struct ast_channel *chan, struct ast_channel *peer,
	struct ast_flags64 *opts, char **opt_args, struct privacy_args *pa)
{

	int res2;
	int loopcount = 0;

	/* Get the user's intro, store it in priv-callerintros/$CID,
	   unless it is already there-- this should be done before the
	   call is actually dialed  */

	/* all ring indications and moh for the caller has been halted as soon as the
	   target extension was picked up. We are going to have to kill some
	   time and make the caller believe the peer hasn't picked up yet */

	if (ast_test_flag64(opts, OPT_MUSICBACK) && !ast_strlen_zero(opt_args[OPT_ARG_MUSICBACK])) {
		char *original_moh = ast_strdupa(ast_channel_musicclass(chan));
		ast_indicate(chan, -1);
		ast_channel_musicclass_set(chan, opt_args[OPT_ARG_MUSICBACK]);
		ast_moh_start(chan, opt_args[OPT_ARG_MUSICBACK], NULL);
		ast_channel_musicclass_set(chan, original_moh);
	} else if (ast_test_flag64(opts, OPT_RINGBACK) || ast_test_flag64(opts, OPT_RING_WITH_EARLY_MEDIA)) {
		ast_indicate(chan, AST_CONTROL_RINGING);
		pa->sentringing++;
	}

	/* Start autoservice on the other chan ?? */
	res2 = ast_autoservice_start(chan);
	/* Now Stream the File */
	for (loopcount = 0; loopcount < 3; loopcount++) {
		if (res2 && loopcount == 0) /* error in ast_autoservice_start() */
			break;
		if (!res2) /* on timeout, play the message again */
			res2 = ast_play_and_wait(peer, "priv-callpending");
		if (!valid_priv_reply(opts, res2))
			res2 = 0;
		/* priv-callpending script:
		   "I have a caller waiting, who introduces themselves as:"
		*/
		if (!res2)
			res2 = ast_play_and_wait(peer, pa->privintro);
		if (!valid_priv_reply(opts, res2))
			res2 = 0;
		/* now get input from the called party, as to their choice */
		if (!res2) {
			/* XXX can we have both, or they are mutually exclusive ? */
			if (ast_test_flag64(opts, OPT_PRIVACY))
				res2 = ast_play_and_wait(peer, "priv-callee-options");
			if (ast_test_flag64(opts, OPT_SCREENING))
				res2 = ast_play_and_wait(peer, "screen-callee-options");
		}

		/*! \page DialPrivacy Dial Privacy scripts
		 * \par priv-callee-options script:
		 * \li Dial 1 if you wish this caller to reach you directly in the future,
		 * 	and immediately connect to their incoming call.
		 * \li Dial 2 if you wish to send this caller to voicemail now and forevermore.
		 * \li Dial 3 to send this caller to the torture menus, now and forevermore.
		 * \li Dial 4 to send this caller to a simple "go away" menu, now and forevermore.
		 * \li Dial 5 to allow this caller to come straight thru to you in the future,
		 * 	but right now, just this once, send them to voicemail.
		 *
		 * \par screen-callee-options script:
		 * \li Dial 1 if you wish to immediately connect to the incoming call
		 * \li Dial 2 if you wish to send this caller to voicemail.
		 * \li Dial 3 to send this caller to the torture menus.
		 * \li Dial 4 to send this caller to a simple "go away" menu.
		 */
		if (valid_priv_reply(opts, res2))
			break;
		/* invalid option */
		res2 = ast_play_and_wait(peer, "vm-sorry");
	}

	if (ast_test_flag64(opts, OPT_MUSICBACK)) {
		ast_moh_stop(chan);
	} else if (ast_test_flag64(opts, OPT_RINGBACK) || ast_test_flag64(opts, OPT_RING_WITH_EARLY_MEDIA)) {
		ast_indicate(chan, -1);
		pa->sentringing = 0;
	}
	ast_autoservice_stop(chan);
	if (ast_test_flag64(opts, OPT_PRIVACY) && (res2 >= '1' && res2 <= '5')) {
		/* map keypresses to various things, the index is res2 - '1' */
		static const char * const _val[] = { "ALLOW", "DENY", "TORTURE", "KILL", "ALLOW" };
		static const int _flag[] = { AST_PRIVACY_ALLOW, AST_PRIVACY_DENY, AST_PRIVACY_TORTURE, AST_PRIVACY_KILL, AST_PRIVACY_ALLOW};
		int i = res2 - '1';
		ast_verb(3, "--Set privacy database entry %s/%s to %s\n",
			opt_args[OPT_ARG_PRIVACY], pa->privcid, _val[i]);
		ast_privacy_set(opt_args[OPT_ARG_PRIVACY], pa->privcid, _flag[i]);
	}
	switch (res2) {
	case '1':
		break;
	case '2':
		ast_copy_string(pa->status, "NOANSWER", sizeof(pa->status));
		break;
	case '3':
		ast_copy_string(pa->status, "TORTURE", sizeof(pa->status));
		break;
	case '4':
		ast_copy_string(pa->status, "DONTCALL", sizeof(pa->status));
		break;
	case '5':
		if (ast_test_flag64(opts, OPT_PRIVACY)) {
			ast_copy_string(pa->status, "NOANSWER", sizeof(pa->status));
			break;
		}
		/* if not privacy, then 5 is the same as "default" case */
	default: /* bad input or -1 if failure to start autoservice */
		/* well, if the user messes up, ... he had his chance... What Is The Best Thing To Do?  */
		/* well, there seems basically two choices. Just patch the caller thru immediately,
			  or,... put 'em thru to voicemail. */
		/* since the callee may have hung up, let's do the voicemail thing, no database decision */
		ast_verb(3, "privacy: no valid response from the callee. Sending the caller to voicemail, the callee isn't responding\n");
		/* XXX should we set status to DENY ? */
		/* XXX what about the privacy flags ? */
		break;
	}

	if (res2 == '1') { /* the only case where we actually connect */
		/* if the intro is NOCALLERID, then there's no reason to leave it on disk, it'll
		   just clog things up, and it's not useful information, not being tied to a CID */
		if (strncmp(pa->privcid, "NOCALLERID", 10) == 0 || ast_test_flag64(opts, OPT_SCREEN_NOINTRO)) {
			ast_filedelete(pa->privintro, NULL);
			if (ast_fileexists(pa->privintro, NULL, NULL) > 0)
				ast_log(LOG_NOTICE, "privacy: ast_filedelete didn't do its job on %s\n", pa->privintro);
			else
				ast_verb(3, "Successfully deleted %s intro file\n", pa->privintro);
		}
		return 0; /* the good exit path */
	} else {
		return -1;
	}
}

/*! \brief returns 1 if successful, 0 or <0 if the caller should 'goto out' */
static int setup_privacy_args(struct privacy_args *pa,
	struct ast_flags64 *opts, char *opt_args[], struct ast_channel *chan)
{
	char callerid[60];
	int res;
	char *l;

	if (ast_channel_caller(chan)->id.number.valid
		&& !ast_strlen_zero(ast_channel_caller(chan)->id.number.str)) {
		l = ast_strdupa(ast_channel_caller(chan)->id.number.str);
		ast_shrink_phone_number(l);
		if (ast_test_flag64(opts, OPT_PRIVACY) ) {
			ast_verb(3, "Privacy DB is '%s', clid is '%s'\n", opt_args[OPT_ARG_PRIVACY], l);
			pa->privdb_val = ast_privacy_check(opt_args[OPT_ARG_PRIVACY], l);
		} else {
			ast_verb(3, "Privacy Screening, clid is '%s'\n", l);
			pa->privdb_val = AST_PRIVACY_UNKNOWN;
		}
	} else {
		char *tnam, *tn2;

		tnam = ast_strdupa(ast_channel_name(chan));
		/* clean the channel name so slashes don't try to end up in disk file name */
		for (tn2 = tnam; *tn2; tn2++) {
			if (*tn2 == '/')  /* any other chars to be afraid of? */
				*tn2 = '=';
		}
		ast_verb(3, "Privacy-- callerid is empty\n");

		snprintf(callerid, sizeof(callerid), "NOCALLERID_%s%s", ast_channel_exten(chan), tnam);
		l = callerid;
		pa->privdb_val = AST_PRIVACY_UNKNOWN;
	}

	ast_copy_string(pa->privcid, l, sizeof(pa->privcid));

	if (strncmp(pa->privcid, "NOCALLERID", 10) != 0 && ast_test_flag64(opts, OPT_SCREEN_NOCALLERID)) {
		/* if callerid is set and OPT_SCREEN_NOCALLERID is set also */
		ast_verb(3, "CallerID set (%s); N option set; Screening should be off\n", pa->privcid);
		pa->privdb_val = AST_PRIVACY_ALLOW;
	} else if (ast_test_flag64(opts, OPT_SCREEN_NOCALLERID) && strncmp(pa->privcid, "NOCALLERID", 10) == 0) {
		ast_verb(3, "CallerID blank; N option set; Screening should happen; dbval is %d\n", pa->privdb_val);
	}

	if (pa->privdb_val == AST_PRIVACY_DENY) {
		ast_verb(3, "Privacy DB reports PRIVACY_DENY for this callerid. Dial reports unavailable\n");
		ast_copy_string(pa->status, "NOANSWER", sizeof(pa->status));
		return 0;
	} else if (pa->privdb_val == AST_PRIVACY_KILL) {
		ast_copy_string(pa->status, "DONTCALL", sizeof(pa->status));
		return 0; /* Is this right? */
	} else if (pa->privdb_val == AST_PRIVACY_TORTURE) {
		ast_copy_string(pa->status, "TORTURE", sizeof(pa->status));
		return 0; /* is this right??? */
	} else if (pa->privdb_val == AST_PRIVACY_UNKNOWN) {
		/* Get the user's intro, store it in priv-callerintros/$CID,
		   unless it is already there-- this should be done before the
		   call is actually dialed  */

		/* make sure the priv-callerintros dir actually exists */
		snprintf(pa->privintro, sizeof(pa->privintro), "%s/sounds/priv-callerintros", ast_config_AST_DATA_DIR);
		if ((res = ast_mkdir(pa->privintro, 0755))) {
			ast_log(LOG_WARNING, "privacy: can't create directory priv-callerintros: %s\n", strerror(res));
			return -1;
		}

		snprintf(pa->privintro, sizeof(pa->privintro), "priv-callerintros/%s", pa->privcid);
		if (ast_fileexists(pa->privintro, NULL, NULL ) > 0 && strncmp(pa->privcid, "NOCALLERID", 10) != 0) {
			/* the DELUX version of this code would allow this caller the
			   option to hear and retape their previously recorded intro.
			*/
		} else {
			int duration; /* for feedback from play_and_wait */
			/* the file doesn't exist yet. Let the caller submit his
			   vocal intro for posterity */
			/* priv-recordintro script:
			   "At the tone, please say your name:"
			*/
			int silencethreshold = ast_dsp_get_threshold_from_settings(THRESHOLD_SILENCE);
			ast_answer(chan);
			res = ast_play_and_record(chan, "priv-recordintro", pa->privintro, 4, "sln", &duration, NULL, silencethreshold, 2000, 0);  /* NOTE: I've reduced the total time to 4 sec */
									/* don't think we'll need a lock removed, we took care of
									   conflicts by naming the pa.privintro file */
			if (res == -1) {
				/* Delete the file regardless since they hung up during recording */
				ast_filedelete(pa->privintro, NULL);
				if (ast_fileexists(pa->privintro, NULL, NULL) > 0)
					ast_log(LOG_NOTICE, "privacy: ast_filedelete didn't do its job on %s\n", pa->privintro);
				else
					ast_verb(3, "Successfully deleted %s intro file\n", pa->privintro);
				return -1;
			}
			if (!ast_streamfile(chan, "vm-dialout", ast_channel_language(chan)) )
				ast_waitstream(chan, "");
		}
	}
	return 1; /* success */
}

static void end_bridge_callback(void *data)
{
	struct ast_channel *chan = data;

	ast_channel_lock(chan);
	ast_channel_stage_snapshot(chan);
	set_duration_var(chan, "ANSWEREDTIME", ast_channel_get_up_time_ms(chan));
	set_duration_var(chan, "DIALEDTIME", ast_channel_get_duration_ms(chan));
	ast_channel_stage_snapshot_done(chan);
	ast_channel_unlock(chan);
}

static void end_bridge_callback_data_fixup(struct ast_bridge_config *bconfig, struct ast_channel *originator, struct ast_channel *terminator) {
	bconfig->end_bridge_callback_data = originator;
}

static int dial_handle_playtones(struct ast_channel *chan, const char *data)
{
	struct ast_tone_zone_sound *ts = NULL;
	int res;
	const char *str = data;

	if (ast_strlen_zero(str)) {
		ast_debug(1,"Nothing to play\n");
		return -1;
	}

	ts = ast_get_indication_tone(ast_channel_zone(chan), str);

	if (ts && ts->data[0]) {
		res = ast_playtones_start(chan, 0, ts->data, 0);
	} else {
		res = -1;
	}

	if (ts) {
		ts = ast_tone_zone_sound_unref(ts);
	}

	if (res) {
		ast_log(LOG_WARNING, "Unable to start playtone \'%s\'\n", str);
	}

	return res;
}

/*!
 * \internal
 * \brief Setup the after bridge goto location on the peer.
 * \since 12.0.0
 *
 * \param chan Calling channel for bridge.
 * \param peer Peer channel for bridge.
 * \param opts Dialing option flags.
 * \param opt_args Dialing option argument strings.
 */
static void setup_peer_after_bridge_goto(struct ast_channel *chan, struct ast_channel *peer, struct ast_flags64 *opts, char *opt_args[])
{
	const char *context;
	const char *extension;
	int priority;

	if (ast_test_flag64(opts, OPT_PEER_H)) {
		ast_channel_lock(chan);
		context = ast_strdupa(ast_channel_context(chan));
		ast_channel_unlock(chan);
		ast_bridge_set_after_h(peer, context);
	} else if (ast_test_flag64(opts, OPT_CALLEE_GO_ON)) {
		ast_channel_lock(chan);
		context = ast_strdupa(ast_channel_context(chan));
		extension = ast_strdupa(ast_channel_exten(chan));
		priority = ast_channel_priority(chan);
		ast_channel_unlock(chan);
		ast_bridge_set_after_go_on(peer, context, extension, priority,
			opt_args[OPT_ARG_CALLEE_GO_ON]);
	}
}

static int dial_exec_full(struct ast_channel *chan, const char *data, struct ast_flags64 *peerflags, int *continue_exec)
{
	int res = -1; /* default: error */
	char *rest, *cur; /* scan the list of destinations */
	struct dial_head out_chans = AST_LIST_HEAD_NOLOCK_INIT_VALUE; /* list of destinations */
	struct chanlist *outgoing;
	struct chanlist *tmp;
	struct ast_channel *peer = NULL;
	int to_answer, to_progress; /* timeouts */
	struct cause_args num = { chan, 0, 0, 0 };
	int cause, hanguptreecause = -1;

	struct ast_bridge_config config = { { 0, } };
	struct timeval calldurationlimit = { 0, };
	char *dtmfcalled = NULL, *dtmfcalling = NULL, *dtmf_progress = NULL;
	char *mf_progress = NULL, *mf_wink = NULL;
	char *sf_progress = NULL, *sf_wink = NULL;
	struct privacy_args pa = {
		.sentringing = 0,
		.privdb_val = 0,
		.status = "INVALIDARGS",
		.canceled = 0,
	};
	int sentringing = 0, moh = 0;
	const char *outbound_group = NULL;
	int result = 0;
	char *parse;
	int opermode = 0;
	int delprivintro = 0;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(peers);
		AST_APP_ARG(timeout);
		AST_APP_ARG(options);
		AST_APP_ARG(url);
	);
	struct ast_flags64 opts = { 0, };
	char *opt_args[OPT_ARG_ARRAY_SIZE];
	int fulldial = 0, num_dialed = 0;
	int ignore_cc = 0;
	char device_name[AST_CHANNEL_NAME];
	char forced_clid_name[AST_MAX_EXTENSION];
	char stored_clid_name[AST_MAX_EXTENSION];
	int force_forwards_only;	/*!< TRUE if force CallerID on call forward only. Legacy behaviour.*/
	/*!
	 * \brief Forced CallerID party information to send.
	 * \note This will not have any malloced strings so do not free it.
	 */
	struct ast_party_id forced_clid;
	/*!
	 * \brief Stored CallerID information if needed.
	 *
	 * \note If OPT_ORIGINAL_CLID set then this is the o option
	 * CallerID.  Otherwise it is the dialplan extension and hint
	 * name.
	 *
	 * \note This will not have any malloced strings so do not free it.
	 */
	struct ast_party_id stored_clid;
	/*!
	 * \brief CallerID party information to store.
	 * \note This will not have any malloced strings so do not free it.
	 */
	struct ast_party_caller caller;
	int max_forwards;
	struct ast_datastore *topology_ds = NULL;
	SCOPE_ENTER(1, "%s: Data: %s\n", ast_channel_name(chan), data);

	/* Reset all DIAL variables back to blank, to prevent confusion (in case we don't reset all of them). */
	ast_channel_lock(chan);
	ast_channel_stage_snapshot(chan);
	pbx_builtin_setvar_helper(chan, "DIALSTATUS", "");
	pbx_builtin_setvar_helper(chan, "DIALEDPEERNUMBER", "");
	pbx_builtin_setvar_helper(chan, "DIALEDPEERNAME", "");
	pbx_builtin_setvar_helper(chan, "ANSWEREDTIME", "");
	pbx_builtin_setvar_helper(chan, "ANSWEREDTIME_MS", "");
	pbx_builtin_setvar_helper(chan, "DIALEDTIME", "");
	pbx_builtin_setvar_helper(chan, "DIALEDTIME_MS", "");
	pbx_builtin_setvar_helper(chan, "RINGTIME", "");
	pbx_builtin_setvar_helper(chan, "RINGTIME_MS", "");
	pbx_builtin_setvar_helper(chan, "PROGRESSTIME", "");
	pbx_builtin_setvar_helper(chan, "PROGRESSTIME_MS", "");
	ast_channel_stage_snapshot_done(chan);
	max_forwards = ast_max_forwards_get(chan);
	ast_channel_unlock(chan);

	if (max_forwards <= 0) {
		ast_log(LOG_WARNING, "Cannot place outbound call from channel '%s'. Max forwards exceeded\n",
				ast_channel_name(chan));
		pbx_builtin_setvar_helper(chan, "DIALSTATUS", "BUSY");
		SCOPE_EXIT_RTN_VALUE(-1, "%s: Max forwards exceeded\n", ast_channel_name(chan));
	}

	if (ast_check_hangup_locked(chan)) {
		/*
		 * Caller hung up before we could dial.  If dial is executed
		 * within an AGI then the AGI has likely eaten all queued
		 * frames before executing the dial in DeadAGI mode.  With
		 * the caller hung up and no pending frames from the caller's
		 * read queue, dial would not know that the call has hung up
		 * until a called channel answers.  It is rather annoying to
		 * whoever just answered the non-existent call.
		 *
		 * Dial should not continue execution in DeadAGI mode, hangup
		 * handlers, or the h exten.
		 */
		ast_verb(3, "Caller hung up before dial.\n");
		pbx_builtin_setvar_helper(chan, "DIALSTATUS", "CANCEL");
		SCOPE_EXIT_RTN_VALUE(-1, "%s: Caller hung up before dial\n", ast_channel_name(chan));
	}

	parse = ast_strdupa(data ?: "");

	AST_STANDARD_APP_ARGS(args, parse);

	if (!ast_strlen_zero(args.options) &&
		ast_app_parse_options64(dial_exec_options, &opts, opt_args, args.options)) {
		pbx_builtin_setvar_helper(chan, "DIALSTATUS", pa.status);
		goto done;
	}

	if (ast_cc_call_init(chan, &ignore_cc)) {
		goto done;
	}

	if (ast_test_flag64(&opts, OPT_SCREEN_NOINTRO) && !ast_strlen_zero(opt_args[OPT_ARG_SCREEN_NOINTRO])) {
		delprivintro = atoi(opt_args[OPT_ARG_SCREEN_NOINTRO]);

		if (delprivintro < 0 || delprivintro > 1) {
			ast_log(LOG_WARNING, "Unknown argument %d specified to n option, ignoring\n", delprivintro);
			delprivintro = 0;
		}
	}

	if (!ast_test_flag64(&opts, OPT_RINGBACK)) {
		opt_args[OPT_ARG_RINGBACK] = NULL;
	}

	if (ast_test_flag64(&opts, OPT_OPERMODE)) {
		opermode = ast_strlen_zero(opt_args[OPT_ARG_OPERMODE]) ? 1 : atoi(opt_args[OPT_ARG_OPERMODE]);
		ast_verb(3, "Setting operator services mode to %d.\n", opermode);
	}

	if (ast_test_flag64(&opts, OPT_DURATION_STOP) && !ast_strlen_zero(opt_args[OPT_ARG_DURATION_STOP])) {
		calldurationlimit.tv_sec = atoi(opt_args[OPT_ARG_DURATION_STOP]);
		if (!calldurationlimit.tv_sec) {
			ast_log(LOG_WARNING, "Dial does not accept S(%s)\n", opt_args[OPT_ARG_DURATION_STOP]);
			pbx_builtin_setvar_helper(chan, "DIALSTATUS", pa.status);
			goto done;
		}
		ast_verb(3, "Setting call duration limit to %.3lf seconds.\n", calldurationlimit.tv_sec + calldurationlimit.tv_usec / 1000000.0);
	}

	if (ast_test_flag64(&opts, OPT_SENDDTMF) && !ast_strlen_zero(opt_args[OPT_ARG_SENDDTMF])) {
		sf_wink = opt_args[OPT_ARG_SENDDTMF];
		dtmfcalled = strsep(&sf_wink, ":");
		dtmfcalling = strsep(&sf_wink, ":");
		dtmf_progress = strsep(&sf_wink, ":");
		mf_progress = strsep(&sf_wink, ":");
		mf_wink = strsep(&sf_wink, ":");
		sf_progress = strsep(&sf_wink, ":");
	}

	if (ast_test_flag64(&opts, OPT_DURATION_LIMIT) && !ast_strlen_zero(opt_args[OPT_ARG_DURATION_LIMIT])) {
		if (ast_bridge_timelimit(chan, &config, opt_args[OPT_ARG_DURATION_LIMIT], &calldurationlimit))
			goto done;
	}

	/* Setup the forced CallerID information to send if used. */
	ast_party_id_init(&forced_clid);
	force_forwards_only = 0;
	if (ast_test_flag64(&opts, OPT_FORCECLID)) {
		if (ast_strlen_zero(opt_args[OPT_ARG_FORCECLID])) {
			ast_channel_lock(chan);
			forced_clid.number.str = ast_strdupa(ast_channel_exten(chan));
			ast_channel_unlock(chan);
			forced_clid_name[0] = '\0';
			forced_clid.name.str = (char *) get_cid_name(forced_clid_name,
				sizeof(forced_clid_name), chan);
			force_forwards_only = 1;
		} else {
			/* Note: The opt_args[OPT_ARG_FORCECLID] string value is altered here. */
			ast_callerid_parse(opt_args[OPT_ARG_FORCECLID], &forced_clid.name.str,
				&forced_clid.number.str);
		}
		if (!ast_strlen_zero(forced_clid.name.str)) {
			forced_clid.name.valid = 1;
		}
		if (!ast_strlen_zero(forced_clid.number.str)) {
			forced_clid.number.valid = 1;
		}
	}
	if (ast_test_flag64(&opts, OPT_FORCE_CID_TAG)
		&& !ast_strlen_zero(opt_args[OPT_ARG_FORCE_CID_TAG])) {
		forced_clid.tag = opt_args[OPT_ARG_FORCE_CID_TAG];
	}
	forced_clid.number.presentation = AST_PRES_ALLOWED_USER_NUMBER_PASSED_SCREEN;
	if (ast_test_flag64(&opts, OPT_FORCE_CID_PRES)
		&& !ast_strlen_zero(opt_args[OPT_ARG_FORCE_CID_PRES])) {
		int pres;

		pres = ast_parse_caller_presentation(opt_args[OPT_ARG_FORCE_CID_PRES]);
		if (0 <= pres) {
			forced_clid.number.presentation = pres;
		}
	}

	/* Setup the stored CallerID information if needed. */
	ast_party_id_init(&stored_clid);
	if (ast_test_flag64(&opts, OPT_ORIGINAL_CLID)) {
		if (ast_strlen_zero(opt_args[OPT_ARG_ORIGINAL_CLID])) {
			ast_channel_lock(chan);
			ast_party_id_set_init(&stored_clid, &ast_channel_caller(chan)->id);
			if (!ast_strlen_zero(ast_channel_caller(chan)->id.name.str)) {
				stored_clid.name.str = ast_strdupa(ast_channel_caller(chan)->id.name.str);
			}
			if (!ast_strlen_zero(ast_channel_caller(chan)->id.number.str)) {
				stored_clid.number.str = ast_strdupa(ast_channel_caller(chan)->id.number.str);
			}
			if (!ast_strlen_zero(ast_channel_caller(chan)->id.subaddress.str)) {
				stored_clid.subaddress.str = ast_strdupa(ast_channel_caller(chan)->id.subaddress.str);
			}
			if (!ast_strlen_zero(ast_channel_caller(chan)->id.tag)) {
				stored_clid.tag = ast_strdupa(ast_channel_caller(chan)->id.tag);
			}
			ast_channel_unlock(chan);
		} else {
			/* Note: The opt_args[OPT_ARG_ORIGINAL_CLID] string value is altered here. */
			ast_callerid_parse(opt_args[OPT_ARG_ORIGINAL_CLID], &stored_clid.name.str,
				&stored_clid.number.str);
			if (!ast_strlen_zero(stored_clid.name.str)) {
				stored_clid.name.valid = 1;
			}
			if (!ast_strlen_zero(stored_clid.number.str)) {
				stored_clid.number.valid = 1;
			}
		}
	} else {
		/*
		 * In case the new channel has no preset CallerID number by the
		 * channel driver, setup the dialplan extension and hint name.
		 */
		stored_clid_name[0] = '\0';
		stored_clid.name.str = (char *) get_cid_name(stored_clid_name,
			sizeof(stored_clid_name), chan);
		if (ast_strlen_zero(stored_clid.name.str)) {
			stored_clid.name.str = NULL;
		} else {
			stored_clid.name.valid = 1;
		}
		ast_channel_lock(chan);
		stored_clid.number.str = ast_strdupa(ast_channel_exten(chan));
		stored_clid.number.valid = 1;
		ast_channel_unlock(chan);
	}

	if (ast_test_flag64(&opts, OPT_RESETCDR)) {
		ast_cdr_reset(ast_channel_name(chan), 0);
	}
	if (ast_test_flag64(&opts, OPT_PRIVACY) && ast_strlen_zero(opt_args[OPT_ARG_PRIVACY]))
		opt_args[OPT_ARG_PRIVACY] = ast_strdupa(ast_channel_exten(chan));

	if (ast_test_flag64(&opts, OPT_PRIVACY) || ast_test_flag64(&opts, OPT_SCREENING)) {
		res = setup_privacy_args(&pa, &opts, opt_args, chan);
		if (res <= 0)
			goto out;
		res = -1; /* reset default */
	}

	if (continue_exec)
		*continue_exec = 0;

	/* If a channel group has been specified, get it for use when we create peer channels */

	ast_channel_lock(chan);
	if ((outbound_group = pbx_builtin_getvar_helper(chan, "OUTBOUND_GROUP_ONCE"))) {
		outbound_group = ast_strdupa(outbound_group);
		pbx_builtin_setvar_helper(chan, "OUTBOUND_GROUP_ONCE", NULL);
	} else if ((outbound_group = pbx_builtin_getvar_helper(chan, "OUTBOUND_GROUP"))) {
		outbound_group = ast_strdupa(outbound_group);
	}
	ast_channel_unlock(chan);

	/* Set per dial instance flags.  These flags are also passed back to RetryDial. */
	ast_copy_flags64(peerflags, &opts, OPT_DTMF_EXIT | OPT_GO_ON | OPT_ORIGINAL_CLID
		| OPT_CALLER_HANGUP | OPT_IGNORE_FORWARDING | OPT_CANCEL_TIMEOUT
		| OPT_ANNOUNCE | OPT_CALLEE_GOSUB | OPT_FORCECLID);

	/* PREDIAL: Run gosub on the caller's channel */
	if (ast_test_flag64(&opts, OPT_PREDIAL_CALLER)
		&& !ast_strlen_zero(opt_args[OPT_ARG_PREDIAL_CALLER])) {
		ast_replace_subargument_delimiter(opt_args[OPT_ARG_PREDIAL_CALLER]);
		ast_app_exec_sub(NULL, chan, opt_args[OPT_ARG_PREDIAL_CALLER], 0);
	}

	/* loop through the list of dial destinations */
	rest = args.peers;
	while ((cur = strsep(&rest, "&"))) {
		struct ast_channel *tc; /* channel for this destination */
		char *number;
		char *tech;
		int i;
		size_t tech_len;
		size_t number_len;
		struct ast_stream_topology *topology;
		struct ast_stream *stream;

		cur = ast_strip(cur);
		if (ast_strlen_zero(cur)) {
			/* No tech/resource in this position. */
			continue;
		}

		/* Get a technology/resource pair */
		number = cur;
		tech = strsep(&number, "/");

		num_dialed++;
		if (ast_strlen_zero(number)) {
			ast_log(LOG_WARNING, "Dial argument takes format (technology/resource)\n");
			goto out;
		}

		tech_len = strlen(tech) + 1;
		number_len = strlen(number) + 1;
		tmp = ast_calloc(1, sizeof(*tmp) + (2 * tech_len) + number_len);
		if (!tmp) {
			goto out;
		}

		/* Save tech, number, and interface. */
		cur = tmp->stuff;
		strcpy(cur, tech);
		tmp->tech = cur;
		cur += tech_len;
		strcpy(cur, tech);
		cur[tech_len - 1] = '/';
		tmp->interface = cur;
		cur += tech_len;
		strcpy(cur, number);
		tmp->number = cur;

		if (opts.flags) {
			/* Set per outgoing call leg options. */
			ast_copy_flags64(tmp, &opts,
				OPT_CANCEL_ELSEWHERE |
				OPT_CALLEE_TRANSFER | OPT_CALLER_TRANSFER |
				OPT_CALLEE_HANGUP | OPT_CALLER_HANGUP |
				OPT_CALLEE_MONITOR | OPT_CALLER_MONITOR |
				OPT_CALLEE_PARK | OPT_CALLER_PARK |
				OPT_CALLEE_MIXMONITOR | OPT_CALLER_MIXMONITOR |
				OPT_RINGBACK | OPT_MUSICBACK | OPT_FORCECLID | OPT_IGNORE_CONNECTEDLINE |
				OPT_RING_WITH_EARLY_MEDIA);
			ast_set2_flag64(tmp, args.url, DIAL_NOFORWARDHTML);
		}

		/* Request the peer */

		ast_channel_lock(chan);
		/*
		 * Seed the chanlist's connected line information with previously
		 * acquired connected line info from the incoming channel.  The
		 * previously acquired connected line info could have been set
		 * through the CONNECTED_LINE dialplan function.
		 */
		ast_party_connected_line_copy(&tmp->connected, ast_channel_connected(chan));

		if (ast_test_flag64(&opts, OPT_TOPOLOGY_PRESERVE)) {
			topology_ds = ast_channel_datastore_find(chan, &topology_ds_info, NULL);

			if (!topology_ds && (topology_ds = ast_datastore_alloc(&topology_ds_info, NULL))) {
				topology_ds->data = ast_stream_topology_clone(ast_channel_get_stream_topology(chan));
				ast_channel_datastore_add(chan, topology_ds);
			}
		}

		if (topology_ds) {
			ao2_ref(topology_ds->data, +1);
			topology = topology_ds->data;
		} else {
			topology = ast_stream_topology_clone(ast_channel_get_stream_topology(chan));
		}

		ast_channel_unlock(chan);

		for (i = 0; i < ast_stream_topology_get_count(topology); ++i) {
			stream = ast_stream_topology_get_stream(topology, i);
			/* For both recvonly and sendonly the stream state reflects our state, that is we
			 * are receiving only and we are sending only. Since we are requesting a
			 * channel for the peer, we need to swap this to reflect what we will be doing.
			 * That is, if we are receiving from Alice then we want to be sending to Bob,
			 * so swap recvonly to sendonly and vice versa.
			 */
			if (ast_stream_get_state(stream) == AST_STREAM_STATE_RECVONLY) {
				ast_stream_set_state(stream, AST_STREAM_STATE_SENDONLY);
			} else if (ast_stream_get_state(stream) == AST_STREAM_STATE_SENDONLY) {
				ast_stream_set_state(stream, AST_STREAM_STATE_RECVONLY);
			}
		}

		tc = ast_request_with_stream_topology(tmp->tech, topology, NULL, chan, tmp->number, &cause);

		ast_stream_topology_free(topology);

		if (!tc) {
			/* If we can't, just go on to the next call */
			/* Failure doesn't necessarily mean user error. DAHDI channels could be busy. */
			ast_log(LOG_NOTICE, "Unable to create channel of type '%s' (cause %d - %s)\n",
				tmp->tech, cause, ast_cause2str(cause));
			handle_cause(cause, &num);
			if (!rest) {
				/* we are on the last destination */
				ast_channel_hangupcause_set(chan, cause);
			}
			if (!ignore_cc && (cause == AST_CAUSE_BUSY || cause == AST_CAUSE_CONGESTION)) {
				if (!ast_cc_callback(chan, tmp->tech, tmp->number, ast_cc_busy_interface)) {
					ast_cc_extension_monitor_add_dialstring(chan, tmp->interface, "");
				}
			}
			chanlist_free(tmp);
			continue;
		}

		ast_channel_get_device_name(tc, device_name, sizeof(device_name));
		if (!ignore_cc) {
			ast_cc_extension_monitor_add_dialstring(chan, tmp->interface, device_name);
		}

		ast_channel_lock_both(tc, chan);
		ast_channel_stage_snapshot(tc);

		pbx_builtin_setvar_helper(tc, "DIALEDPEERNUMBER", tmp->number);

		/* Setup outgoing SDP to match incoming one */
		if (!AST_LIST_FIRST(&out_chans) && !rest && CAN_EARLY_BRIDGE(peerflags, chan, tc)) {
			/* We are on the only destination. */
			ast_rtp_instance_early_bridge_make_compatible(tc, chan);
		}

		/* Inherit specially named variables from parent channel */
		ast_channel_inherit_variables(chan, tc);
		ast_channel_datastore_inherit(chan, tc);
		ast_max_forwards_decrement(tc);

		ast_channel_appl_set(tc, "AppDial");
		ast_channel_data_set(tc, "(Outgoing Line)");

		memset(ast_channel_whentohangup(tc), 0, sizeof(*ast_channel_whentohangup(tc)));

		/* Determine CallerID to store in outgoing channel. */
		ast_party_caller_set_init(&caller, ast_channel_caller(tc));
		if (ast_test_flag64(peerflags, OPT_ORIGINAL_CLID)) {
			caller.id = stored_clid;
			ast_channel_set_caller_event(tc, &caller, NULL);
			ast_set_flag64(tmp, DIAL_CALLERID_ABSENT);
		} else if (ast_strlen_zero(S_COR(ast_channel_caller(tc)->id.number.valid,
			ast_channel_caller(tc)->id.number.str, NULL))) {
			/*
			 * The new channel has no preset CallerID number by the channel
			 * driver.  Use the dialplan extension and hint name.
			 */
			caller.id = stored_clid;
			if (!caller.id.name.valid
				&& !ast_strlen_zero(S_COR(ast_channel_connected(chan)->id.name.valid,
					ast_channel_connected(chan)->id.name.str, NULL))) {
				/*
				 * No hint name available.  We have a connected name supplied by
				 * the dialplan we can use instead.
				 */
				caller.id.name.valid = 1;
				caller.id.name = ast_channel_connected(chan)->id.name;
			}
			ast_channel_set_caller_event(tc, &caller, NULL);
			ast_set_flag64(tmp, DIAL_CALLERID_ABSENT);
		} else if (ast_strlen_zero(S_COR(ast_channel_caller(tc)->id.name.valid, ast_channel_caller(tc)->id.name.str,
			NULL))) {
			/* The new channel has no preset CallerID name by the channel driver. */
			if (!ast_strlen_zero(S_COR(ast_channel_connected(chan)->id.name.valid,
				ast_channel_connected(chan)->id.name.str, NULL))) {
				/*
				 * We have a connected name supplied by the dialplan we can
				 * use instead.
				 */
				caller.id.name.valid = 1;
				caller.id.name = ast_channel_connected(chan)->id.name;
				ast_channel_set_caller_event(tc, &caller, NULL);
			}
		}

		/* Determine CallerID for outgoing channel to send. */
		if (ast_test_flag64(peerflags, OPT_FORCECLID) && !force_forwards_only) {
			struct ast_party_connected_line connected;

			ast_party_connected_line_set_init(&connected, ast_channel_connected(tc));
			connected.id = forced_clid;
			ast_channel_set_connected_line(tc, &connected, NULL);
		} else {
			ast_connected_line_copy_from_caller(ast_channel_connected(tc), ast_channel_caller(chan));
		}

		ast_party_redirecting_copy(ast_channel_redirecting(tc), ast_channel_redirecting(chan));

		ast_channel_dialed(tc)->transit_network_select = ast_channel_dialed(chan)->transit_network_select;

		ast_channel_req_accountcodes(tc, chan, AST_CHANNEL_REQUESTOR_BRIDGE_PEER);
		if (ast_strlen_zero(ast_channel_musicclass(tc))) {
			ast_channel_musicclass_set(tc, ast_channel_musicclass(chan));
		}

		/* Pass ADSI CPE and transfer capability */
		ast_channel_adsicpe_set(tc, ast_channel_adsicpe(chan));
		ast_channel_transfercapability_set(tc, ast_channel_transfercapability(chan));

		/* If we have an outbound group, set this peer channel to it */
		if (outbound_group)
			ast_app_group_set_channel(tc, outbound_group);
		/* If the calling channel has the ANSWERED_ELSEWHERE flag set, inherit it. This is to support local channels */
		if (ast_channel_hangupcause(chan) == AST_CAUSE_ANSWERED_ELSEWHERE)
			ast_channel_hangupcause_set(tc, AST_CAUSE_ANSWERED_ELSEWHERE);

		/* Check if we're forced by configuration */
		if (ast_test_flag64(&opts, OPT_CANCEL_ELSEWHERE))
			 ast_channel_hangupcause_set(tc, AST_CAUSE_ANSWERED_ELSEWHERE);


		/* Inherit context and extension */
		ast_channel_dialcontext_set(tc, ast_channel_context(chan));
		ast_channel_exten_set(tc, ast_channel_exten(chan));

		ast_channel_stage_snapshot_done(tc);

		/* Save the original channel name to detect call pickup masquerading in. */
		tmp->orig_chan_name = ast_strdup(ast_channel_name(tc));

		ast_channel_unlock(tc);
		ast_channel_unlock(chan);

		/* Put channel in the list of outgoing thingies. */
		tmp->chan = tc;
		AST_LIST_INSERT_TAIL(&out_chans, tmp, node);
	}

	/* As long as we attempted to dial valid peers, don't throw a warning. */
	/* If a DAHDI peer is busy, out_chans will be empty so checking list size is misleading. */
	if (!num_dialed) {
		ast_verb(3, "No devices or endpoints to dial (technology/resource)\n");
		if (continue_exec) {
			/* There is no point in having RetryDial try again */
			*continue_exec = 1;
		}
		strcpy(pa.status, "CHANUNAVAIL");
		res = 0;
		goto out;
	}

	/*
	 * PREDIAL: Run gosub on all of the callee channels
	 *
	 * We run the callee predial before ast_call() in case the user
	 * wishes to do something on the newly created channels before
	 * the channel does anything important.
	 *
	 * Inside the target gosub we will be able to do something with
	 * the newly created channel name ie: now the calling channel
	 * can know what channel will be used to call the destination
	 * ex: now we will know that SIP/abc-123 is calling SIP/def-124
	 */
	if (ast_test_flag64(&opts, OPT_PREDIAL_CALLEE)
		&& !ast_strlen_zero(opt_args[OPT_ARG_PREDIAL_CALLEE])
		&& !AST_LIST_EMPTY(&out_chans)) {
		const char *predial_callee;

		ast_replace_subargument_delimiter(opt_args[OPT_ARG_PREDIAL_CALLEE]);
		predial_callee = ast_app_expand_sub_args(chan, opt_args[OPT_ARG_PREDIAL_CALLEE]);
		if (predial_callee) {
			ast_autoservice_start(chan);
			AST_LIST_TRAVERSE(&out_chans, tmp, node) {
				ast_pre_call(tmp->chan, predial_callee);
			}
			ast_autoservice_stop(chan);
			ast_free((char *) predial_callee);
		}
	}

	/* Start all outgoing calls */
	AST_LIST_TRAVERSE_SAFE_BEGIN(&out_chans, tmp, node) {
		res = ast_call(tmp->chan, tmp->number, 0); /* Place the call, but don't wait on the answer */
		ast_channel_lock(chan);

		/* check the results of ast_call */
		if (res) {
			/* Again, keep going even if there's an error */
			ast_debug(1, "ast call on peer returned %d\n", res);
			ast_verb(3, "Couldn't call %s\n", tmp->interface);
			if (ast_channel_hangupcause(tmp->chan)) {
				ast_channel_hangupcause_set(chan, ast_channel_hangupcause(tmp->chan));
			}
			ast_channel_unlock(chan);
			ast_cc_call_failed(chan, tmp->chan, tmp->interface);
			ast_hangup(tmp->chan);
			tmp->chan = NULL;
			AST_LIST_REMOVE_CURRENT(node);
			chanlist_free(tmp);
			continue;
		}

		ast_channel_publish_dial(chan, tmp->chan, tmp->number, NULL);
		ast_channel_unlock(chan);

		ast_verb(3, "Called %s\n", tmp->interface);
		ast_set_flag64(tmp, DIAL_STILLGOING);

		/* If this line is up, don't try anybody else */
		if (ast_channel_state(tmp->chan) == AST_STATE_UP) {
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END;

	if (ast_strlen_zero(args.timeout)) {
		to_answer = -1;
		to_progress = -1;
	} else {
		char *anstimeout = strsep(&args.timeout, "^");
		if (!ast_strlen_zero(anstimeout)) {
			to_answer = atoi(anstimeout);
			if (to_answer > 0) {
				to_answer *= 1000;
			} else {
				ast_log(LOG_WARNING, "Invalid answer timeout specified: '%s'. Setting timeout to infinite\n", args.timeout);
				to_answer = -1;
			}
		} else {
			to_answer = -1;
		}
		if (!ast_strlen_zero(args.timeout)) {
			to_progress = atoi(args.timeout);
			if (to_progress > 0) {
				to_progress *= 1000;
			} else {
				ast_log(LOG_WARNING, "Invalid progress timeout specified: '%s'. Setting timeout to infinite\n", args.timeout);
				to_progress = -1;
			}
		} else {
			to_progress = -1;
		}
	}

	outgoing = AST_LIST_FIRST(&out_chans);
	if (!outgoing) {
		strcpy(pa.status, "CHANUNAVAIL");
		if (fulldial == num_dialed) {
			res = -1;
			goto out;
		}
	} else {
		/* Our status will at least be NOANSWER */
		strcpy(pa.status, "NOANSWER");
		if (ast_test_flag64(outgoing, OPT_MUSICBACK)) {
			moh = 1;
			if (!ast_strlen_zero(opt_args[OPT_ARG_MUSICBACK])) {
				char *original_moh = ast_strdupa(ast_channel_musicclass(chan));
				ast_channel_musicclass_set(chan, opt_args[OPT_ARG_MUSICBACK]);
				ast_moh_start(chan, opt_args[OPT_ARG_MUSICBACK], NULL);
				ast_channel_musicclass_set(chan, original_moh);
			} else {
				ast_moh_start(chan, NULL, NULL);
			}
			ast_indicate(chan, AST_CONTROL_PROGRESS);
		} else if (ast_test_flag64(outgoing, OPT_RINGBACK) || ast_test_flag64(outgoing, OPT_RING_WITH_EARLY_MEDIA)) {
			if (!ast_strlen_zero(opt_args[OPT_ARG_RINGBACK])) {
				if (dial_handle_playtones(chan, opt_args[OPT_ARG_RINGBACK])){
					ast_indicate(chan, AST_CONTROL_RINGING);
					sentringing++;
				} else {
					ast_indicate(chan, AST_CONTROL_PROGRESS);
				}
			} else {
				ast_indicate(chan, AST_CONTROL_RINGING);
				sentringing++;
			}
		}
	}

	peer = wait_for_answer(chan, &out_chans, &to_answer, &to_progress, peerflags, opt_args, &pa, &num, &result,
		dtmf_progress, mf_progress, mf_wink, sf_progress, sf_wink,
		(ast_test_flag64(&opts, OPT_HEARPULSING) ? 1 : 0),
		ignore_cc, &forced_clid, &stored_clid, &config);

	if (!peer) {
		if (result) {
			res = result;
		} else if (to_answer) { /* Musta gotten hung up */
			res = -1;
		} else { /* Nobody answered, next please? */
			res = 0;
		}
	} else {
		const char *number;
		const char *name;
		int dial_end_raised = 0;
		int cause = -1;

		if (ast_test_flag64(&opts, OPT_CALLER_ANSWER)) {
			ast_answer(chan);
		}

		/* Ah ha!  Someone answered within the desired timeframe.  Of course after this
		   we will always return with -1 so that it is hung up properly after the
		   conversation.  */

		if (ast_test_flag64(&opts, OPT_HANGUPCAUSE)
			&& !ast_strlen_zero(opt_args[OPT_ARG_HANGUPCAUSE])) {
			cause = ast_str2cause(opt_args[OPT_ARG_HANGUPCAUSE]);
			if (cause <= 0) {
				if (!strcasecmp(opt_args[OPT_ARG_HANGUPCAUSE], "NONE")) {
					cause = 0;
				} else if (sscanf(opt_args[OPT_ARG_HANGUPCAUSE], "%30d", &cause) != 1
					|| cause < 0) {
					ast_log(LOG_WARNING, "Invalid cause given to Dial(...Q(<cause>)): \"%s\"\n",
						opt_args[OPT_ARG_HANGUPCAUSE]);
					cause = -1;
				}
			}
		}
		hanguptree(&out_chans, peer, cause >= 0 ? cause : AST_CAUSE_ANSWERED_ELSEWHERE);

		/* If appropriate, log that we have a destination channel and set the answer time */

		ast_channel_lock(peer);
		name = ast_strdupa(ast_channel_name(peer));

		number = pbx_builtin_getvar_helper(peer, "DIALEDPEERNUMBER");
		if (ast_strlen_zero(number)) {
			number = NULL;
		} else {
			number = ast_strdupa(number);
		}
		ast_channel_unlock(peer);

		ast_channel_lock(chan);
		ast_channel_stage_snapshot(chan);

		strcpy(pa.status, "ANSWER");
		pbx_builtin_setvar_helper(chan, "DIALSTATUS", pa.status);

		pbx_builtin_setvar_helper(chan, "DIALEDPEERNAME", name);
		pbx_builtin_setvar_helper(chan, "DIALEDPEERNUMBER", number);

		ast_channel_stage_snapshot_done(chan);
		ast_channel_unlock(chan);

		if (!ast_strlen_zero(args.url) && ast_channel_supports_html(peer) ) {
			ast_debug(1, "app_dial: sendurl=%s.\n", args.url);
			ast_channel_sendurl( peer, args.url );
		}
		if ( (ast_test_flag64(&opts, OPT_PRIVACY) || ast_test_flag64(&opts, OPT_SCREENING)) && pa.privdb_val == AST_PRIVACY_UNKNOWN) {
			if (do_privacy(chan, peer, &opts, opt_args, &pa)) {
				ast_channel_publish_dial(chan, peer, NULL, pa.status);
				/* hang up on the callee -- he didn't want to talk anyway! */
				ast_autoservice_chan_hangup_peer(chan, peer);
				res = 0;
				goto out;
			}
		}
		if (!ast_test_flag64(&opts, OPT_ANNOUNCE) || ast_strlen_zero(opt_args[OPT_ARG_ANNOUNCE])) {
			res = 0;
		} else {
			int digit = 0;
			struct ast_channel *chans[2];
			struct ast_channel *active_chan;
			char *calledfile = NULL, *callerfile = NULL;
			int calledstream = 0, callerstream = 0;

			chans[0] = chan;
			chans[1] = peer;

			/* we need to stream the announcement(s) when the OPT_ARG_ANNOUNCE (-A) is set */
			callerfile = opt_args[OPT_ARG_ANNOUNCE];
			calledfile = strsep(&callerfile, ":");

			/* stream the file(s) */
			if (!ast_strlen_zero(calledfile)) {
				res = ast_streamfile(peer, calledfile, ast_channel_language(peer));
				if (res) {
					res = 0;
					ast_log(LOG_ERROR, "error streaming file '%s' to callee\n", calledfile);
				} else {
					calledstream = 1;
				}
			}
			if (!ast_strlen_zero(callerfile)) {
				res = ast_streamfile(chan, callerfile, ast_channel_language(chan));
				if (res) {
					res = 0;
					ast_log(LOG_ERROR, "error streaming file '%s' to caller\n", callerfile);
				} else {
					callerstream = 1;
				}
			}

			/* can't use ast_waitstream, because we're streaming two files at once, and can't block
				We'll need to handle both channels at once. */

			ast_channel_set_flag(peer, AST_FLAG_END_DTMF_ONLY);
			while (ast_channel_stream(peer) || ast_channel_stream(chan)) {
				int mspeer, mschan;

				mspeer = ast_sched_wait(ast_channel_sched(peer));
				mschan = ast_sched_wait(ast_channel_sched(chan));

				if (calledstream) {
					if (mspeer < 0 && !ast_channel_timingfunc(peer)) {
						ast_stopstream(peer);
						calledstream = 0;
					}
				}
				if (callerstream) {
					if (mschan < 0 && !ast_channel_timingfunc(chan)) {
						ast_stopstream(chan);
						callerstream = 0;
					}
				}

				if (!calledstream && !callerstream) {
					break;
				}

				if (mspeer < 0)
					mspeer = 1000;

				if (mschan < 0)
					mschan = 1000;

				/* wait for the lowest maximum of the two */
				active_chan = ast_waitfor_n(chans, 2, (mspeer > mschan ? &mschan : &mspeer));
				if (active_chan) {
					struct ast_channel *other_chan;
					struct ast_frame *fr = ast_read(active_chan);

					if (!fr) {
						ast_autoservice_chan_hangup_peer(chan, peer);
						res = -1;
						goto done;
					}
					switch (fr->frametype) {
					case AST_FRAME_DTMF_END:
						digit = fr->subclass.integer;
						if (active_chan == peer && strchr(AST_DIGIT_ANY, res)) {
							ast_stopstream(peer);
							res = ast_senddigit(chan, digit, 0);
						}
						break;
					case AST_FRAME_CONTROL:
						switch (fr->subclass.integer) {
						case AST_CONTROL_HANGUP:
							ast_frfree(fr);
							ast_autoservice_chan_hangup_peer(chan, peer);
							res = -1;
							goto done;
						case AST_CONTROL_CONNECTED_LINE:
							/* Pass COLP update to the other channel. */
							if (active_chan == chan) {
								other_chan = peer;
							} else {
								other_chan = chan;
							}
							if (ast_channel_connected_line_sub(active_chan, other_chan, fr, 1)) {
								ast_indicate_data(other_chan, fr->subclass.integer,
									fr->data.ptr, fr->datalen);
							}
							break;
						default:
							break;
						}
						break;
					default:
						/* Ignore all others */
						break;
					}
					ast_frfree(fr);
				}
				ast_sched_runq(ast_channel_sched(peer));
				ast_sched_runq(ast_channel_sched(chan));
			}
			ast_channel_clear_flag(peer, AST_FLAG_END_DTMF_ONLY);
		}

		if (chan && peer && ast_test_flag64(&opts, OPT_GOTO) && !ast_strlen_zero(opt_args[OPT_ARG_GOTO])) {
			/* chan and peer are going into the PBX; as such neither are considered
			 * outgoing channels any longer */
			ast_channel_clear_flag(chan, AST_FLAG_OUTGOING);

			ast_replace_subargument_delimiter(opt_args[OPT_ARG_GOTO]);
			ast_parseable_goto(chan, opt_args[OPT_ARG_GOTO]);
			/* peer goes to the same context and extension as chan, so just copy info from chan*/
			ast_channel_lock(peer);
			ast_channel_stage_snapshot(peer);
			ast_clear_flag(ast_channel_flags(peer), AST_FLAG_OUTGOING);
			ast_channel_context_set(peer, ast_channel_context(chan));
			ast_channel_exten_set(peer, ast_channel_exten(chan));
			ast_channel_priority_set(peer, ast_channel_priority(chan) + 2);
			ast_channel_stage_snapshot_done(peer);
			ast_channel_unlock(peer);
			if (ast_pbx_start(peer)) {
				ast_autoservice_chan_hangup_peer(chan, peer);
			}
			if (continue_exec)
				*continue_exec = 1;
			res = 0;
			ast_channel_publish_dial(chan, peer, NULL, "ANSWER");
			goto done;
		}

		if (ast_test_flag64(&opts, OPT_CALLEE_GOSUB) && !ast_strlen_zero(opt_args[OPT_ARG_CALLEE_GOSUB])) {
			const char *gosub_result_peer;
			char *gosub_argstart;
			char *gosub_args = NULL;
			int gosub_res = -1;

			ast_replace_subargument_delimiter(opt_args[OPT_ARG_CALLEE_GOSUB]);
			gosub_argstart = strchr(opt_args[OPT_ARG_CALLEE_GOSUB], ',');
			if (gosub_argstart) {
				const char *what_is_s = "s";
				*gosub_argstart = 0;
				if (!ast_exists_extension(peer, opt_args[OPT_ARG_CALLEE_GOSUB], "s", 1, S_COR(ast_channel_caller(peer)->id.number.valid, ast_channel_caller(peer)->id.number.str, NULL)) &&
					 ast_exists_extension(peer, opt_args[OPT_ARG_CALLEE_GOSUB], "~~s~~", 1, S_COR(ast_channel_caller(peer)->id.number.valid, ast_channel_caller(peer)->id.number.str, NULL))) {
					what_is_s = "~~s~~";
				}
				if (ast_asprintf(&gosub_args, "%s,%s,1(%s)", opt_args[OPT_ARG_CALLEE_GOSUB], what_is_s, gosub_argstart + 1) < 0) {
					gosub_args = NULL;
				}
				*gosub_argstart = ',';
			} else {
				const char *what_is_s = "s";
				if (!ast_exists_extension(peer, opt_args[OPT_ARG_CALLEE_GOSUB], "s", 1, S_COR(ast_channel_caller(peer)->id.number.valid, ast_channel_caller(peer)->id.number.str, NULL)) &&
					 ast_exists_extension(peer, opt_args[OPT_ARG_CALLEE_GOSUB], "~~s~~", 1, S_COR(ast_channel_caller(peer)->id.number.valid, ast_channel_caller(peer)->id.number.str, NULL))) {
					what_is_s = "~~s~~";
				}
				if (ast_asprintf(&gosub_args, "%s,%s,1", opt_args[OPT_ARG_CALLEE_GOSUB], what_is_s) < 0) {
					gosub_args = NULL;
				}
			}
			if (gosub_args) {
				gosub_res = ast_app_exec_sub(chan, peer, gosub_args, 0);
				ast_free(gosub_args);
			} else {
				ast_log(LOG_ERROR, "Could not Allocate string for Gosub arguments -- Gosub Call Aborted!\n");
			}

			ast_channel_lock_both(chan, peer);

			if (!gosub_res && (gosub_result_peer = pbx_builtin_getvar_helper(peer, "GOSUB_RESULT"))) {
				char *gosub_transfer_dest;
				char *gosub_result = ast_strdupa(gosub_result_peer);
				const char *gosub_retval = pbx_builtin_getvar_helper(peer, "GOSUB_RETVAL");

				/* Inherit return value from the peer, so it can be used in the master */
				if (gosub_retval) {
					pbx_builtin_setvar_helper(chan, "GOSUB_RETVAL", gosub_retval);
				}

				ast_channel_unlock(peer);
				ast_channel_unlock(chan);

				if (!strcasecmp(gosub_result, "BUSY")) {
					ast_copy_string(pa.status, gosub_result, sizeof(pa.status));
					ast_set_flag64(peerflags, OPT_GO_ON);
					gosub_res = -1;
				} else if (!strcasecmp(gosub_result, "CONGESTION") || !strcasecmp(gosub_result, "CHANUNAVAIL")) {
					ast_copy_string(pa.status, gosub_result, sizeof(pa.status));
					ast_set_flag64(peerflags, OPT_GO_ON);
					gosub_res = -1;
				} else if (!strcasecmp(gosub_result, "CONTINUE")) {
					/* Hangup peer and continue with the next extension priority. */
					ast_set_flag64(peerflags, OPT_GO_ON);
					gosub_res = -1;
				} else if (!strcasecmp(gosub_result, "ABORT")) {
					/* Hangup both ends unless the caller has the g flag */
					gosub_res = -1;
				} else if (!strncasecmp(gosub_result, "GOTO:", 5)) {
					gosub_transfer_dest = gosub_result + 5;
					gosub_res = -1;
					/* perform a transfer to a new extension */
					if (strchr(gosub_transfer_dest, '^')) { /* context^exten^priority*/
						ast_replace_subargument_delimiter(gosub_transfer_dest);
					}
					if (!ast_parseable_goto(chan, gosub_transfer_dest)) {
						ast_set_flag64(peerflags, OPT_GO_ON);
					}
				}
				if (gosub_res) {
					res = gosub_res;
					if (!dial_end_raised) {
						ast_channel_publish_dial(chan, peer, NULL, gosub_result);
						dial_end_raised = 1;
					}
				}
			} else {
				ast_channel_unlock(peer);
				ast_channel_unlock(chan);
			}
		}

		if (!res) {

			/* None of the Dial options changed our status; inform
			 * everyone that this channel answered
			 */
			if (!dial_end_raised) {
				ast_channel_publish_dial(chan, peer, NULL, "ANSWER");
				dial_end_raised = 1;
			}

			if (!ast_tvzero(calldurationlimit)) {
				struct timeval whentohangup = ast_tvadd(ast_tvnow(), calldurationlimit);
				ast_channel_lock(peer);
				ast_channel_whentohangup_set(peer, &whentohangup);
				ast_channel_unlock(peer);
			}
			if (!ast_strlen_zero(dtmfcalled)) {
				ast_verb(3, "Sending DTMF '%s' to the called party.\n", dtmfcalled);
				res = ast_dtmf_stream(peer, chan, dtmfcalled, 250, 0);
			}
			if (!ast_strlen_zero(dtmfcalling)) {
				ast_verb(3, "Sending DTMF '%s' to the calling party.\n", dtmfcalling);
				res = ast_dtmf_stream(chan, peer, dtmfcalling, 250, 0);
			}
		}

		if (res) { /* some error */
			if (!ast_check_hangup(chan) && ast_check_hangup(peer)) {
				ast_channel_hangupcause_set(chan, ast_channel_hangupcause(peer));
			}
			setup_peer_after_bridge_goto(chan, peer, &opts, opt_args);
			if (ast_bridge_setup_after_goto(peer)
				|| ast_pbx_start(peer)) {
				ast_autoservice_chan_hangup_peer(chan, peer);
			}
			res = -1;
		} else {
			if (ast_test_flag64(peerflags, OPT_CALLEE_TRANSFER))
				ast_set_flag(&(config.features_callee), AST_FEATURE_REDIRECT);
			if (ast_test_flag64(peerflags, OPT_CALLER_TRANSFER))
				ast_set_flag(&(config.features_caller), AST_FEATURE_REDIRECT);
			if (ast_test_flag64(peerflags, OPT_CALLEE_HANGUP))
				ast_set_flag(&(config.features_callee), AST_FEATURE_DISCONNECT);
			if (ast_test_flag64(peerflags, OPT_CALLER_HANGUP))
				ast_set_flag(&(config.features_caller), AST_FEATURE_DISCONNECT);
			if (ast_test_flag64(peerflags, OPT_CALLEE_MONITOR))
				ast_set_flag(&(config.features_callee), AST_FEATURE_AUTOMON);
			if (ast_test_flag64(peerflags, OPT_CALLER_MONITOR))
				ast_set_flag(&(config.features_caller), AST_FEATURE_AUTOMON);
			if (ast_test_flag64(peerflags, OPT_CALLEE_PARK))
				ast_set_flag(&(config.features_callee), AST_FEATURE_PARKCALL);
			if (ast_test_flag64(peerflags, OPT_CALLER_PARK))
				ast_set_flag(&(config.features_caller), AST_FEATURE_PARKCALL);
			if (ast_test_flag64(peerflags, OPT_CALLEE_MIXMONITOR))
				ast_set_flag(&(config.features_callee), AST_FEATURE_AUTOMIXMON);
			if (ast_test_flag64(peerflags, OPT_CALLER_MIXMONITOR))
				ast_set_flag(&(config.features_caller), AST_FEATURE_AUTOMIXMON);

			config.end_bridge_callback = end_bridge_callback;
			config.end_bridge_callback_data = chan;
			config.end_bridge_callback_data_fixup = end_bridge_callback_data_fixup;

			if (moh) {
				moh = 0;
				ast_moh_stop(chan);
			} else if (sentringing) {
				sentringing = 0;
				ast_indicate(chan, -1);
			}
			/* Be sure no generators are left on it and reset the visible indication */
			ast_deactivate_generator(chan);
			ast_channel_visible_indication_set(chan, 0);
			/* Make sure channels are compatible */
			res = ast_channel_make_compatible(chan, peer);
			if (res < 0) {
				ast_log(LOG_WARNING, "Had to drop call because I couldn't make %s compatible with %s\n", ast_channel_name(chan), ast_channel_name(peer));
				ast_autoservice_chan_hangup_peer(chan, peer);
				res = -1;
				goto done;
			}
			if (opermode) {
				struct oprmode oprmode;

				oprmode.peer = peer;
				oprmode.mode = opermode;

				ast_channel_setoption(chan, AST_OPTION_OPRMODE, &oprmode, sizeof(oprmode), 0);
			}
			setup_peer_after_bridge_goto(chan, peer, &opts, opt_args);

			res = ast_bridge_call(chan, peer, &config);
		}
	}
out:
	if (moh) {
		moh = 0;
		ast_moh_stop(chan);
	} else if (sentringing) {
		sentringing = 0;
		ast_indicate(chan, -1);
	}

	if (delprivintro && ast_fileexists(pa.privintro, NULL, NULL) > 0) {
		ast_filedelete(pa.privintro, NULL);
		if (ast_fileexists(pa.privintro, NULL, NULL) > 0) {
			ast_log(LOG_NOTICE, "privacy: ast_filedelete didn't do its job on %s\n", pa.privintro);
		} else {
			ast_verb(3, "Successfully deleted %s intro file\n", pa.privintro);
		}
	}

	ast_channel_early_bridge(chan, NULL);
	/* forward 'answered elsewhere' if we received it */
	if (ast_channel_hangupcause(chan) == AST_CAUSE_ANSWERED_ELSEWHERE || ast_test_flag64(&opts, OPT_CANCEL_ELSEWHERE)) {
		hanguptreecause = AST_CAUSE_ANSWERED_ELSEWHERE;
	} else if (pa.canceled) { /* Caller canceled */
		if (ast_channel_hangupcause(chan))
			hanguptreecause = ast_channel_hangupcause(chan);
		else
			hanguptreecause = AST_CAUSE_NORMAL_CLEARING;
	}
	hanguptree(&out_chans, NULL, hanguptreecause);
	pbx_builtin_setvar_helper(chan, "DIALSTATUS", pa.status);
	ast_debug(1, "Exiting with DIALSTATUS=%s.\n", pa.status);

	if ((ast_test_flag64(peerflags, OPT_GO_ON)) && !ast_check_hangup(chan) && (res != AST_PBX_INCOMPLETE)) {
		if (!ast_tvzero(calldurationlimit))
			memset(ast_channel_whentohangup(chan), 0, sizeof(*ast_channel_whentohangup(chan)));
		res = 0;
	}

done:
	if (config.answer_topology) {
		ast_trace(2, "%s Cleaning up topology: %p %s\n",
			peer ? ast_channel_name(peer) : "<no channel>", &config.answer_topology,
			ast_str_tmp(256, ast_stream_topology_to_str(config.answer_topology, &STR_TMP)));

		/*
		 * At this point, the channel driver that answered should have bumped the
		 * topology refcount for itself.  Here we're cleaning up the reference we added
		 * in wait_for_answer().
		 */
		ast_stream_topology_free(config.answer_topology);
	}
	if (config.warning_sound) {
		ast_free((char *)config.warning_sound);
	}
	if (config.end_sound) {
		ast_free((char *)config.end_sound);
	}
	if (config.start_sound) {
		ast_free((char *)config.start_sound);
	}
	ast_ignore_cc(chan);
	SCOPE_EXIT_RTN_VALUE(res, "%s: Done\n", ast_channel_name(chan));
}

static int dial_exec(struct ast_channel *chan, const char *data)
{
	struct ast_flags64 peerflags;

	memset(&peerflags, 0, sizeof(peerflags));

	return dial_exec_full(chan, data, &peerflags, NULL);
}

static int retrydial_exec(struct ast_channel *chan, const char *data)
{
	char *parse;
	const char *context = NULL;
	int sleepms = 0, loops = 0, res = -1;
	struct ast_flags64 peerflags = { 0, };
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(announce);
		AST_APP_ARG(sleep);
		AST_APP_ARG(retries);
		AST_APP_ARG(dialdata);
	);

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "RetryDial requires an argument!\n");
		return -1;
	}

	parse = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, parse);

	if (!ast_strlen_zero(args.sleep) && (sleepms = atoi(args.sleep)))
		sleepms *= 1000;

	if (!ast_strlen_zero(args.retries)) {
		loops = atoi(args.retries);
	}

	if (!args.dialdata) {
		ast_log(LOG_ERROR, "%s requires a 4th argument (dialdata)\n", rapp);
		goto done;
	}

	if (sleepms < 1000)
		sleepms = 10000;

	if (!loops)
		loops = -1; /* run forever */

	ast_channel_lock(chan);
	context = pbx_builtin_getvar_helper(chan, "EXITCONTEXT");
	context = !ast_strlen_zero(context) ? ast_strdupa(context) : NULL;
	ast_channel_unlock(chan);

	res = 0;
	while (loops) {
		int continue_exec;

		ast_channel_data_set(chan, "Retrying");
		if (ast_test_flag(ast_channel_flags(chan), AST_FLAG_MOH))
			ast_moh_stop(chan);

		res = dial_exec_full(chan, args.dialdata, &peerflags, &continue_exec);
		if (continue_exec)
			break;

		if (res == 0) {
			if (ast_test_flag64(&peerflags, OPT_DTMF_EXIT)) {
				if (!ast_strlen_zero(args.announce)) {
					if (ast_fileexists(args.announce, NULL, ast_channel_language(chan)) > 0) {
						if (!(res = ast_streamfile(chan, args.announce, ast_channel_language(chan))))
							ast_waitstream(chan, AST_DIGIT_ANY);
					} else
						ast_log(LOG_WARNING, "Announce file \"%s\" specified in Retrydial does not exist\n", args.announce);
				}
				if (!res && sleepms) {
					if (!ast_test_flag(ast_channel_flags(chan), AST_FLAG_MOH))
						ast_moh_start(chan, NULL, NULL);
					res = ast_waitfordigit(chan, sleepms);
				}
			} else {
				if (!ast_strlen_zero(args.announce)) {
					if (ast_fileexists(args.announce, NULL, ast_channel_language(chan)) > 0) {
						if (!(res = ast_streamfile(chan, args.announce, ast_channel_language(chan))))
							res = ast_waitstream(chan, "");
					} else
						ast_log(LOG_WARNING, "Announce file \"%s\" specified in Retrydial does not exist\n", args.announce);
				}
				if (sleepms) {
					if (!ast_test_flag(ast_channel_flags(chan), AST_FLAG_MOH))
						ast_moh_start(chan, NULL, NULL);
					if (!res)
						res = ast_waitfordigit(chan, sleepms);
				}
			}
		}

		if (res < 0 || res == AST_PBX_INCOMPLETE) {
			break;
		} else if (res > 0) { /* Trying to send the call elsewhere (1 digit ext) */
			if (onedigit_goto(chan, context, (char) res, 1)) {
				res = 0;
				break;
			}
		}
		loops--;
	}
	if (loops == 0)
		res = 0;
	else if (res == 1)
		res = 0;

	if (ast_test_flag(ast_channel_flags(chan), AST_FLAG_MOH))
		ast_moh_stop(chan);
 done:
	return res;
}

static int unload_module(void)
{
	int res;

	res = ast_unregister_application(app);
	res |= ast_unregister_application(rapp);

	return res;
}

static int load_module(void)
{
	int res;

	res = ast_register_application_xml(app, dial_exec);
	res |= ast_register_application_xml(rapp, retrydial_exec);

	return res;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "Dialing Application",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.requires = "ccss",
);
