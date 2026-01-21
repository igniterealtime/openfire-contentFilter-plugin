/*
 * Copyright (C) 2004-2008 Jive Software, 2025 Ignite Realtime Foundation. All rights reserved.
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.dom4j.Element;
import org.xmpp.packet.Packet;

/**
 * Filters message content using regular expressions. If a content mask is
 * provided message content will be altered.
 *
 * @author Conor Hayes
 */
public class ContentFilter {

    private String patterns;

    private final Collection<Pattern> compiledPatterns = new ArrayList<>();

    private String mask;

    private boolean caseSensitive;

    /**
     * A default instance will allow all message content.
     *
     * @see #setPatterns(String)
     * @see #setMask(String)
     */
    public ContentFilter() {
    }

    /**
     * Set the patterns to use for searching content.
     *
     * @param regExps a comma separated String of regular expressions
     */
    public void setPatterns(String regExps) {
        recompilePatterns(regExps, this.caseSensitive);
    }

    public String getPatterns() {
        return this.patterns;
    }

    /**
     * Clears all patterns. Calling this method means that all message content
     * will be allowed.
     */
    public void clearPatterns() {
        patterns = null;
        compiledPatterns.clear();
    }

    private void recompilePatterns(String patterns, boolean isCaseSensitive)
    {
        this.caseSensitive = isCaseSensitive;
        if (patterns != null) {
            this.patterns = patterns;
            String[] data = patterns.split(",");

            compiledPatterns.clear();

            for (String datum : data) {
                compiledPatterns.add(Pattern.compile(datum, isCaseSensitive ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE));
            }
        }
        else {
            clearPatterns();
        }
    }

    /**
     * Set the content replacement mask.
     *
     * @param mask the mask to use when replacing content
     */
    public void setMask(String mask) {
        this.mask = mask;
    }

    /**
     * @return the current mask or null if none has been set
     */
    public String getMask() {
        return mask;
    }

    /**
     * Clears the content mask.
     *
     * @see #setMask(String)
     */
    public void clearMask() {
        mask = null;
    }


    /**
     * @return true if the filter is currently masking content, false otherwise
     */
    public boolean isMaskingContent() {
        return mask != null;
    }

    /**
     * Defines if the patters are to be applied in a case-sensitive manner.
     *
     * @param caseSensitive desired case sensitivity for pattern matching
     */
    public void setCaseSensitive(boolean caseSensitive)
    {
        recompilePatterns(patterns, caseSensitive);
    }

    /**
     * Returns if case sensitivity is enabled.
     *
     * @return true if the filter is currently case-sensitive
     */
    public boolean isCaseSensitive()
    {
        return this.caseSensitive;
    }

    /**
     * Filters packet content.
     *
     * @param stanza the packet to filter, its content may be altered if there
     *            are content matches and a content mask is set
     * @return true if the msg content matched up, false otherwise
     */
    public boolean filter(Packet stanza) {
        return process(stanza.getElement());
    }

    private boolean process(Element element) {
        
        boolean matched = mask(element);
        
        if (!matched || isMaskingContent())
        {
            //only check children if no match has yet been found            
            //or all content must be masked
            Iterator<Element> iter = element.elementIterator();
            while (iter.hasNext()) {
                matched |= process(iter.next());
            }
        }
        
        return matched;
    }
    
    private boolean mask(Element element) {
        
        boolean match = false;
        
        String content = element.getText();
        
        if ((content != null) && (!content.isEmpty())) {
            
            for (Pattern pattern : compiledPatterns) {                
                
                Matcher matcher = pattern.matcher(content);
                
                if (matcher.find()) {
                    
                    match = true;
                    
                    if (isMaskingContent()) {
                        content = matcher.replaceAll(mask);
                        element.setText(content);
                    }
                }  
            }    
        }
        
        return match;
    }
}
