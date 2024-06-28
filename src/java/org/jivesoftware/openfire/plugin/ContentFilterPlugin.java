/*
 * Copyright (C) 2004-2008 Jive Software. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.plugin;

import java.io.File;
import java.util.regex.PatternSyntaxException;

import org.jivesoftware.openfire.MessageRouter;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.util.EmailService;
import org.jivesoftware.util.SystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;
import org.xmpp.packet.Presence;

/**
 * Content filter plugin.
 * 
 * @author Conor Hayes
 */
public class ContentFilterPlugin implements Plugin, PacketInterceptor {

    private static final Logger Log = LoggerFactory.getLogger(ContentFilterPlugin.class);

    private static String pluginName = "Content Filter";

    /**
     * The expected value is a boolean, if true the user identified by the value
     * of the property #VIOLATION_NOTIFICATION_CONTACT_PROPERTY will be notified
     * every time there is a content match, otherwise no notification will be
     * sent. Then default value is false.
     */
    public static final SystemProperty<Boolean> VIOLATION_NOTIFICATION_ENABLED_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.violation.notification.enabled")
        .setDynamic(true)
        .setDefaultValue(false)
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a username. The default value is "admin".
     */
    public static final SystemProperty<String> VIOLATION_NOTIFICATION_CONTACT_PROPERTY = SystemProperty.Builder.ofType(String.class)
        .setKey("plugin.contentFilter.violation.notification.contact")
        .setDynamic(true)
        .setDefaultValue("admin")
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a boolean, if true the user identified by the value
     * of the property #VIOLATION_NOTIFICATION_CONTACT_PROPERTY, will also
     * receive a copy of the offending packet. The default value is false.
     */
    public static final SystemProperty<Boolean> VIOLATION_INCLUDE_ORIGNAL_PACKET_ENABLED_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.violation.notification.include.original.enabled")
        .setDynamic(true)
        .setDefaultValue(false)
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a boolean, if true the user identified by the value
     * of the property #VIOLATION_NOTIFICATION_CONTACT_PROPERTY, will receive
     * notification by IM. The default value is true.
     */
    public static final SystemProperty<Boolean> VIOLATION_NOTIFICATION_BY_IM_ENABLED_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.violation.notification.by.im.enabled")
        .setDynamic(true)
        .setDefaultValue(true)
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a boolean, if true the user identified by the value
     * of the property #VIOLATION_NOTIFICATION_CONTACT_PROPERTY, will receive
     * notification by email. The default value is false.
     */
    public static final SystemProperty<Boolean> VIOLATION_NOTIFICATION_BY_EMAIL_ENABLED_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.violation.notification.by.email.enabled")
        .setDynamic(true)
        .setDefaultValue(false)
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a boolean, if true the sender will be notified when
     * a message is rejected, otherwise the message will be silently
     * rejected,i.e. the sender will not know that the message was rejected and
     * the receiver will not get the message. The default value is false.
     */
    public static final SystemProperty<Boolean> REJECTION_NOTIFICATION_ENABLED_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.rejection.notification.enabled")
        .setDynamic(true)
        .setDefaultValue(false)
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a string, containing the desired message for the
     * sender notification.
     */
    public static final SystemProperty<String> REJECTION_MSG_PROPERTY = SystemProperty.Builder.ofType(String.class)
        .setKey("plugin.contentFilter.rejection.msg")
        .setDynamic(true)
        .setDefaultValue("Message rejected. This is an automated server response.")
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a boolean, if true the value of #PATTERNS_PROPERTY
     * will be used for pattern matching.
     */
    public static final SystemProperty<Boolean> PATTERNS_ENABLED_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.patterns.enabled")
        .setDynamic(true)
        .setDefaultValue(false)
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a comma separated string of regular expressions.
     */
    public static final SystemProperty<String> PATTERNS_PROPERTY = SystemProperty.Builder.ofType(String.class)
        .setKey("plugin.contentFilter.patterns")
        .setDynamic(true)
        .setDefaultValue("fox,dog")
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a boolean, if true Presence packets will be
     * filtered
     */
    public static final SystemProperty<Boolean> FILTER_STATUS_ENABLED_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.filter.status.enabled")
        .setDynamic(true)
        .setDefaultValue(false)
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a boolean, if true the value of #MASK_PROPERTY will
     * be used to mask matching content.
     */
    public static final SystemProperty<Boolean> MASK_ENABLED_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.mask.enabled")
        .setDynamic(true)
        .setDefaultValue(false)
        .setPlugin(pluginName)
        .build();

    /**
     * The expected value is a string. If this property is set any matching
     * content will not be rejected but masked with the given value. Setting a
     * content mask means that property #SENDER_NOTIFICATION_ENABLED_PROPERTY is
     * ignored. The default value is "**".
     */
    public static final SystemProperty<String> MASK_PROPERTY = SystemProperty.Builder.ofType(String.class)
        .setKey("plugin.contentFilter.mask")
        .setDynamic(true)
        .setDefaultValue("***")
        .setPlugin(pluginName)
        .build();
    
    /**
     * The expected value is a boolean, if false packets whose contents matches one
     * of the supplied regular expressions will be rejected, otherwise the packet will
     * be accepted and may be optionally masked. The default value is false.
     * @see #MASK_ENABLED_PROPERTY
     */
    public static final SystemProperty<Boolean> ALLOW_ON_MATCH_PROPERTY = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("plugin.contentFilter.allow.on.match")
        .setDynamic(true)
        .setDefaultValue(false)
        .setPlugin(pluginName)
        .build();

    /**
     * the hook into the interceptor chain
     */
    private InterceptorManager interceptorManager;

    /**
     * used to send violation notifications
     */
    private MessageRouter messageRouter;

    /**
     * delegate that does the real work of this plugin
     */
    private ContentFilter contentFilter;

    /**
     * flags if sender should be notified of rejections
     */
    private boolean rejectionNotificationEnabled;

    /**
     * the rejection msg to send
     */
    private String rejectionMessage;

    /**
     * flags if content matches should result in admin notification
     */
    private boolean violationNotificationEnabled;

    /**
     * the admin user to send violation notifications to
     */
    private String violationContact;

    /**
     * flags if original packet should be included in the message to the
     * violation contact.
     */
    private boolean violationIncludeOriginalPacketEnabled;

    /**
     * flags if violation contact should be notified by IM.
     */
    private boolean violationNotificationByIMEnabled;

    /**
     * flags if violation contact should be notified by email.
     */
    private boolean violationNotificationByEmailEnabled;

    /**
     * flag if patterns should be used
     */
    private boolean patternsEnabled;

    /**
     * the patterns to use
     */
    private String patterns;

    /**
     * flag if Presence packets should be filtered.
     */
    private boolean filterStatusEnabled;

    /**
     * flag if mask should be used
     */
    private boolean maskEnabled;

    /**
     * the mask to use
     */
    private String mask;
    
    /**
     * flag if matching content should be accepted or rejected. 
     */
    private boolean allowOnMatch;
    
    /**
     * violation notification messages will be from this JID
     */
    private JID violationNotificationFrom;

    public ContentFilterPlugin() {
        contentFilter = new ContentFilter();
        interceptorManager = InterceptorManager.getInstance();
        violationNotificationFrom = new JID(XMPPServer.getInstance()
                .getServerInfo().getXMPPDomain());
        messageRouter = XMPPServer.getInstance().getMessageRouter();
    }

    /**
     * Restores the plugin defaults.
     */
    public void reset() {
        setViolationNotificationEnabled(false);
        setViolationContact("admin");
        setViolationNotificationByIMEnabled(true);
        setViolationNotificationByEmailEnabled(false);
        setViolationIncludeOriginalPacketEnabled(false);
        setRejectionNotificationEnabled(false);
        setRejectionMessage("Message rejected. This is an automated server response");
        setPatternsEnabled(false);
        setPatterns("fox,dog");        
        setFilterStatusEnabled(false);
        setMaskEnabled(false);
        setMask("***");
        setAllowOnMatch(false);
    }
    
    public boolean isAllowOnMatch() {
        return allowOnMatch;
    }
    
    public void setAllowOnMatch(boolean allow) {
        allowOnMatch = allow;
        ALLOW_ON_MATCH_PROPERTY.setValue(allow);
        
        changeContentFilterMask();
    }
    
    public boolean isMaskEnabled() {
        return maskEnabled;
    }

    public void setMaskEnabled(boolean enabled) {
        maskEnabled = enabled;
        MASK_ENABLED_PROPERTY.setValue(enabled);

        changeContentFilterMask();
    }

    public void setMask(String mas) {
        mask = mas;
        MASK_PROPERTY.setValue(mas);

        changeContentFilterMask();
    }

    private void changeContentFilterMask() {
        if (allowOnMatch && maskEnabled) {
            contentFilter.setMask(mask);
        } else {
            contentFilter.clearMask();
        }
    }

    public String getMask() {
        return mask;
    }

    public boolean isPatternsEnabled() {
        return patternsEnabled;
    }

    public void setPatternsEnabled(boolean enabled) {
        patternsEnabled = enabled;
        PATTERNS_ENABLED_PROPERTY.setValue(enabled);

        changeContentFilterPatterns();
    }

    public void setPatterns(String patt) {
        patterns = patt;
        PATTERNS_PROPERTY.setValue(patt);

        changeContentFilterPatterns();
    }

    public boolean isFilterStatusEnabled() {
        return filterStatusEnabled;
    }

    public void setFilterStatusEnabled(boolean enabled) {
        filterStatusEnabled = enabled;
        FILTER_STATUS_ENABLED_PROPERTY.setValue(enabled);
    }

    private void changeContentFilterPatterns() {
        if (patternsEnabled) {
            contentFilter.setPatterns(patterns);
        } else {
            contentFilter.clearPatterns();
        }
    }

    public String getPatterns() {
        return patterns;
    }

    public boolean isRejectionNotificationEnabled() {
        return rejectionNotificationEnabled;
    }

    public void setRejectionNotificationEnabled(boolean enabled) {
        rejectionNotificationEnabled = enabled;
        REJECTION_NOTIFICATION_ENABLED_PROPERTY.setValue(enabled);
    }

    public String getRejectionMessage() {
        return rejectionMessage;
    }

    public void setRejectionMessage(String message) {
        this.rejectionMessage = message;
        REJECTION_MSG_PROPERTY.setValue(message);
    }

    public boolean isViolationNotificationEnabled() {
        return violationNotificationEnabled;
    }

    public void setViolationNotificationEnabled(boolean enabled) {
        violationNotificationEnabled = enabled;
        VIOLATION_NOTIFICATION_ENABLED_PROPERTY.setValue(enabled);
    }

    public void setViolationContact(String contact) {
        violationContact = contact;
        VIOLATION_NOTIFICATION_CONTACT_PROPERTY.setValue(contact);
    }

    public String getViolationContact() {
        return violationContact;
    }

    public boolean isViolationIncludeOriginalPacketEnabled() {
        return violationIncludeOriginalPacketEnabled;
    }

    public void setViolationIncludeOriginalPacketEnabled(boolean enabled) {
        violationIncludeOriginalPacketEnabled = enabled;
        VIOLATION_INCLUDE_ORIGNAL_PACKET_ENABLED_PROPERTY.setValue(enabled);
    }

    public boolean isViolationNotificationByIMEnabled() {
        return violationNotificationByIMEnabled;
    }

    public void setViolationNotificationByIMEnabled(boolean enabled) {
        violationNotificationByIMEnabled = enabled;
        VIOLATION_NOTIFICATION_BY_IM_ENABLED_PROPERTY.setValue(enabled);
    }

    public boolean isViolationNotificationByEmailEnabled() {
        return violationNotificationByEmailEnabled;
    }

    public void setViolationNotificationByEmailEnabled(boolean enabled) {
        violationNotificationByEmailEnabled = enabled;
        VIOLATION_NOTIFICATION_BY_EMAIL_ENABLED_PROPERTY.setValue(enabled);
    }

    public void initializePlugin(PluginManager pManager, File pluginDirectory) {
        // configure this plugin
        initFilter();

        // register with interceptor manager
        interceptorManager.addInterceptor(this);
    }

    private void initFilter() {
        // default to false
        violationNotificationEnabled = VIOLATION_NOTIFICATION_ENABLED_PROPERTY.getValue();

        // default to "admin"
        violationContact = VIOLATION_NOTIFICATION_CONTACT_PROPERTY.getValue();

        // default to true
        violationNotificationByIMEnabled = VIOLATION_NOTIFICATION_BY_IM_ENABLED_PROPERTY.getValue();

        // default to false
        violationNotificationByEmailEnabled = VIOLATION_NOTIFICATION_BY_EMAIL_ENABLED_PROPERTY.getValue();

        // default to false
        violationIncludeOriginalPacketEnabled = VIOLATION_INCLUDE_ORIGNAL_PACKET_ENABLED_PROPERTY.getValue();

        // default to false
        rejectionNotificationEnabled = REJECTION_NOTIFICATION_ENABLED_PROPERTY.getValue();

        // default to english
        rejectionMessage = REJECTION_MSG_PROPERTY.getValue();

        // default to false
        patternsEnabled = PATTERNS_ENABLED_PROPERTY.getValue();

        // default to "fox,dog"
        patterns = PATTERNS_PROPERTY.getValue();

        try {
            changeContentFilterPatterns();
        }
        catch (PatternSyntaxException e) {
            Log.warn("Resetting to default patterns of ContentFilterPlugin", e);
            // Existing patterns are invalid so reset to default ones
            setPatterns("fox,dog");
        }

        // default to false
        filterStatusEnabled = FILTER_STATUS_ENABLED_PROPERTY.getValue();

        // default to false
        maskEnabled = MASK_ENABLED_PROPERTY.getValue();

        // default to "***"
        mask = MASK_PROPERTY.getValue();
        
        // default to false
        allowOnMatch = ALLOW_ON_MATCH_PROPERTY.getValue();
        
        //v1.2.2 backwards compatibility
        if (maskEnabled) {
            allowOnMatch = true;
        }
        
        changeContentFilterMask();
    }

    /**
     * @see org.jivesoftware.openfire.container.Plugin#destroyPlugin()
     */
    public void destroyPlugin() {
        // unregister with interceptor manager
        interceptorManager.removeInterceptor(this);
    }

    public void interceptPacket(Packet packet, Session session, boolean read,
            boolean processed) throws PacketRejectedException {

        if (isValidTargetPacket(packet, read, processed)) {

            Packet original = packet;

            if (Log.isDebugEnabled()) {
                Log.debug("Content filter: intercepted packet:"
                        + original.toString());
            }

            // make a copy of the original packet only if required,
            // as it's an expensive operation
            if (violationNotificationEnabled
                    && violationIncludeOriginalPacketEnabled && maskEnabled) {
                original = packet.createCopy();
            }

            // filter the packet
            boolean contentMatched = contentFilter.filter(packet);

            if (Log.isDebugEnabled()) {
                Log.debug("Content filter: content matched? " + contentMatched);
            }

            // notify admin of violations
            if (contentMatched && violationNotificationEnabled) {

                if (Log.isDebugEnabled()) {
                    Log.debug("Content filter: sending violation notification");
                    Log.debug("Content filter: include original msg? "
                            + this.violationIncludeOriginalPacketEnabled);
                }

                sendViolationNotification(original);
            }

            // msg will either be rejected silently, rejected with
            // some notification to sender, or allowed and optionally masked.
            // allowing a message without masking can be useful if the admin
            // simply wants to get notified of matches without interrupting
            // the conversation in the  (spy mode!)
            if (contentMatched) {
                
                if (allowOnMatch) {
                                        
                    if (Log.isDebugEnabled()) {
                        Log.debug("Content filter: allowed content:"
                                + packet.toString());
                    }
                    
                    // no further action required
                    
                } else {
                    // msg must be rejected
                    if (Log.isDebugEnabled()) {
                        Log.debug("Content filter: rejecting packet");
                    }

                    PacketRejectedException rejected = new PacketRejectedException(
                            "Packet rejected with disallowed content!");

                    if (rejectionNotificationEnabled) {
                        // let the sender know about the rejection, this is
                        // only possible/useful if the content is not masked
                        rejected.setRejectionMessage(rejectionMessage);
                    }

                    throw rejected;
                }
            }
        }
    }

    private boolean isValidTargetPacket(Packet packet, boolean read,
            boolean processed) {
        return patternsEnabled
                && !processed
                && read
                && (packet instanceof Message || (filterStatusEnabled && packet instanceof Presence))
                && isNotServerGeneratedPacket(packet);
    }
    
    private boolean isNotServerGeneratedPacket(Packet packet) {
        return packet.getFrom().getNode() != null
            && packet.getFrom().getNode().length() > 0;
    }

    private void sendViolationNotification(Packet originalPacket) {
        String subject = "Content filter notification! ("
                + originalPacket.getFrom().getNode() + ")";

        String body;
        if (originalPacket instanceof Message) {
            Message originalMsg = (Message) originalPacket;
            body = "Disallowed content detected in message from:"
                    + originalMsg.getFrom()
                    + " to:"
                    + originalMsg.getTo()
                    + ", message was "
                    + (allowOnMatch ? "allowed" + (contentFilter.isMaskingContent() ? " and masked." : " but not masked.") : "rejected.")
                    + (violationIncludeOriginalPacketEnabled ? "\nOriginal subject:"
                            + (originalMsg.getSubject() != null ? originalMsg
                                    .getSubject() : "")
                            + "\nOriginal content:"
                            + (originalMsg.getBody() != null ? originalMsg
                                    .getBody() : "")
                            : "");

        } else {
            // presence
            Presence originalPresence = (Presence) originalPacket;
            body = "Disallowed status detected in presence from:"
                    + originalPresence.getFrom()
                    + ", status was "
                    + (allowOnMatch ? "allowed" + (contentFilter.isMaskingContent() ? " and masked." : " but not masked.") : "rejected.")
                    + (violationIncludeOriginalPacketEnabled ? "\nOriginal status:"
                            + originalPresence.getStatus()
                            : "");
        }

        if (violationNotificationByIMEnabled) {

            if (Log.isDebugEnabled()) {
                Log.debug("Content filter: sending IM notification");
            }
            sendViolationNotificationIM(subject, body);
        }

        if (violationNotificationByEmailEnabled) {

            if (Log.isDebugEnabled()) {
                Log.debug("Content filter: sending email notification");
            }
            sendViolationNotificationEmail(subject, body);
        }
    }

    private void sendViolationNotificationIM(String subject, String body) {
        Message message = createServerMessage(subject, body);
        // TODO consider spinning off a separate thread here,
        // in high volume situations, it will result in
        // in faster response and notification is not required
        // to be real time.
        messageRouter.route(message);
    }

    private Message createServerMessage(String subject, String body) {
        Message message = new Message();
        message.setTo(violationContact + "@"
                + violationNotificationFrom.getDomain());
        message.setFrom(violationNotificationFrom);
        message.setSubject(subject);
        message.setBody(body);
        return message;
    }

    private void sendViolationNotificationEmail(String subject, String body) {
        try {
            User user = UserManager.getInstance().getUser(violationContact);
            
            //this is automatically put on another thread for execution.
            EmailService.getInstance().sendMessage(user.getName(), user.getEmail(), "Openfire",
                "no_reply@" + violationNotificationFrom.getDomain(), subject, body, null);

        }
        catch (Throwable e) {
            // catch throwable in case email setup is invalid
            Log.error("Content Filter: Failed to send email, please review Openfire setup", e);
        }
    }
}
