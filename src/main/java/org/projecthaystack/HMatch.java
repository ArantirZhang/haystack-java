package org.projecthaystack;

public class HMatch {

  // Some examples:
  // match("aa","a") → false
  // match("aa","aa") → true
  // match("aaa","aa") → false
  // match("aa", "*") → true
  // match("aa", "a*") → true
  // match("ab", "?*") → true
  // match("aab", "c*a*b") → false
  // -------------------------------------------------------------------------------------------------------------------
  //1.use two pointers to go through strings
  // pointer str in s, pointer patt in p
  // pstar to show if p == '*'
  // ms record the last matched postion for back track, if encounter p !='*' check back to this mark at s

  // This is much faster than DP sol O(n)
  public static boolean match(String s, String p) { //double pointers
    int s_cur = 0; // current reading position
    int p_cur = 0;
    int star_cur = -1;
    int ms = 0;
    while (s_cur < s.length()) {
      //match
      if (p_cur < p.length() && (s.charAt(s_cur) == p.charAt(p_cur) || p.charAt(p_cur) == '?')) {
        ++s_cur;
        ++p_cur;
        //p=='*', step cur in p, record current s position for back track
      }
      else if (p_cur < p.length() && p.charAt(p_cur) == '*') {
        star_cur = p_cur;
        ms = s_cur;
        ++p_cur;
        //p!='*', only step cur in p, go back to last matched postion and update ms to next postion
      }
      else if (star_cur != -1) {
        p_cur = star_cur + 1;
        ++ms;
        s_cur = ms;
        //no * at all
      }
      else
      {
        return false;
      }
    }

    //check for remain char in p
    while (p_cur < p.length() && p.charAt(p_cur) == '*') {
      p_cur++;
    }
    return p_cur == p.length();
  }

  // match with spliter
  // Some examples:
  // matchAll("aa","a*|b|c") → true
  public static boolean matchAll(String string, String pattern) {
    if (!string.contains("|")) return match(string, pattern);

    String[] matches = string.split("\\|");
    for (String p : matches) {
      if (match(string, p)) {
        return true;
      }
    }
    return false;
  }
}
