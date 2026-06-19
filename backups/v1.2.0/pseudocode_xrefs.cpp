#include <hexrays.hpp>
#include <xref.hpp>

#include <cctype>
#include <cstdlib>
#include <string>

namespace
{

constexpr char ACTION_NAME[] = "pseudocode_xrefs:show";
constexpr char ACTION_LABEL[] = "Show xrefs to item";
constexpr char ACTION_HOTKEY[] = "K";
constexpr char VTABLE_ACTION_NAME[] = "pseudocode_xrefs:show_vtable_offset";
constexpr char VTABLE_ACTION_LABEL[] = "Show VTABLE byte offset";
constexpr char VTABLE_ACTION_HOTKEY[] = "J";

struct vtable_marker_t
{
  int line = -1;
  int start_column = 0;
  int end_column = 0;
  uval_t byte_offset = 0;
  uval_t slot = 0;
  qstring object_name;
};

using vtable_markers_t = qvector<vtable_marker_t>;

bool is_identifier_char(char c);

void append_colored(qstring *output, const char *text, const char *color)
{
  output->append(SCOLOR_ON);
  output->append(color);
  output->append(text);
  output->append(SCOLOR_OFF);
  output->append(color);
}

const char *find_identifier_after(
        const qstring &tagged_line,
        const std::string &identifier,
        size_t plain_column)
{
  const char *search = tag_advance(tagged_line.c_str(), int(plain_column));
  while ( true )
  {
    const char *found = strstr(search, identifier.c_str());
    if ( found == nullptr )
      return nullptr;

    const char before = found == tagged_line.c_str() ? '\0' : found[-1];
    const char after = found[identifier.length()];
    if ( !is_identifier_char(before) && !is_identifier_char(after) )
      return found;
    search = found + identifier.length();
  }
}

char find_identifier_color(
        const qstring &tagged_line,
        const std::string &identifier,
        size_t plain_column)
{
  const char *found = find_identifier_after(tagged_line, identifier, plain_column);
  if ( found != nullptr
    && found - tagged_line.c_str() >= 2
    && found[-2] == COLOR_ON )
  {
    return found[-1];
  }

  // Hex-Rays uses this color for local variables and parameters in pseudocode.
  return *SCOLOR_LIBNAME;
}

bool is_identifier_start(char c)
{
  const uchar value = uchar(c);
  return std::isalpha(value) != 0 || c == '_';
}

bool is_identifier_char(char c)
{
  const uchar value = uchar(c);
  return std::isalnum(value) != 0 || c == '_';
}

bool find_vtable_pattern(
        const std::string &plain,
        size_t search_from,
        size_t *match_start,
        size_t *match_end,
        size_t *object_start,
        size_t *object_end,
        uval_t *byte_offset)
{
  size_t marker = plain.find("*(*", search_from);
  while ( marker != std::string::npos )
  {
    size_t cursor = marker + 3;
    if ( cursor < plain.size() && is_identifier_start(plain[cursor]) )
    {
      const size_t object_begin = cursor++;
      while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
        ++cursor;
      const size_t object_finish = cursor;

      while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
        ++cursor;
      if ( cursor < plain.size() && plain[cursor++] == '+' )
      {
        while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
          ++cursor;
        const size_t number_begin = cursor;
        if ( cursor + 2 <= plain.size()
          && plain[cursor] == '0'
          && (plain[cursor + 1] == 'x' || plain[cursor + 1] == 'X') )
        {
          cursor += 2;
          const size_t digits_begin = cursor;
          while ( cursor < plain.size()
               && std::isxdigit(uchar(plain[cursor])) != 0 )
          {
            ++cursor;
          }
          if ( cursor > digits_begin )
          {
            const std::string number = plain.substr(number_begin, cursor - number_begin);
            while ( cursor < plain.size()
                 && (plain[cursor] == 'u'
                  || plain[cursor] == 'U'
                  || plain[cursor] == 'l'
                  || plain[cursor] == 'L') )
            {
              ++cursor;
            }
            while ( cursor < plain.size()
                 && std::isspace(uchar(plain[cursor])) != 0 )
            {
              ++cursor;
            }
            if ( cursor < plain.size() && plain[cursor] == ')' )
            {
              size_t finish = cursor + 1;
              while ( finish < plain.size() && plain[finish] == ')' )
                ++finish;
              if ( finish < plain.size() && plain[finish] == '(' )
              {
                size_t begin = marker;
                if ( begin > 0 && plain[begin - 1] == '(' )
                  --begin;

                *match_start = begin;
                *match_end = finish;
                *object_start = object_begin;
                *object_end = object_finish;
                *byte_offset = uval_t(::strtoull(number.c_str(), nullptr, 0));
                return true;
              }
            }
          }
        }
      }
    }
    marker = plain.find("*(*", marker + 3);
  }
  return false;
}

bool rewrite_vtable_line(
        simpleline_t *line,
        int line_number,
        vtable_markers_t *markers)
{
  qstring plain_qstr;
  tag_remove(&plain_qstr, line->line);
  const std::string plain(plain_qstr.c_str());
  const qstring original = line->line;

  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  size_t search_from = 0;
  ptrdiff_t column_delta = 0;
  bool changed = false;
  qstring rewritten;

  while ( search_from < plain.size() )
  {
    size_t match_start = 0;
    size_t match_end = 0;
    size_t object_start = 0;
    size_t object_end = 0;
    uval_t byte_offset = 0;
    if ( !find_vtable_pattern(
          plain,
          search_from,
          &match_start,
          &match_end,
          &object_start,
          &object_end,
          &byte_offset) )
    {
      break;
    }
    if ( byte_offset % pointer_size != 0 )
    {
      search_from = match_end;
      continue;
    }

    const char *raw_begin = original.c_str();
    const char *raw_search_from = tag_advance(raw_begin, int(search_from));
    const char *raw_prefix_end = tag_advance(raw_begin, int(match_start));
    const char *raw_object_begin = tag_advance(raw_begin, int(object_start));
    const char *raw_object_end = tag_advance(raw_begin, int(object_end));
    rewritten.append(raw_search_from, raw_prefix_end - raw_search_from);
    rewritten.append(raw_object_begin, raw_object_end - raw_object_begin);

    append_colored(&rewritten, "->", SCOLOR_SYMBOL);
    const int token_start =
      int(ptrdiff_t(match_start) + column_delta + ptrdiff_t(object_end - object_start) + 2);
    append_colored(&rewritten, "VTABLE", SCOLOR_DEFAULT);
    append_colored(&rewritten, "[", SCOLOR_SYMBOL);

    const uval_t slot = byte_offset / pointer_size;
    qstring slot_text;
    slot_text.sprnt("0x%" FMT_64 "X", uint64(slot));
    append_colored(&rewritten, slot_text.c_str(), SCOLOR_NUMBER);
    append_colored(&rewritten, "]", SCOLOR_SYMBOL);
    const int token_end = token_start + 8 + int(slot_text.length());

    vtable_marker_t &marker = markers->push_back();
    marker.line = line_number;
    marker.start_column = token_start;
    marker.end_column = token_end;
    marker.byte_offset = byte_offset;
    marker.slot = slot;
    marker.object_name = plain.substr(object_start, object_end - object_start).c_str();

    const size_t replacement_length =
      object_end - object_start + 10 + slot_text.length();
    column_delta += ptrdiff_t(replacement_length) - ptrdiff_t(match_end - match_start);
    search_from = match_end;
    changed = true;
  }

  if ( changed )
  {
    const char *raw_tail = tag_advance(original.c_str(), int(search_from));
    rewritten.append(raw_tail);
    line->line.swap(rewritten);
  }
  return changed;
}

bool normalize_vtable_colors(simpleline_t *line)
{
  qstring plain_qstr;
  tag_remove(&plain_qstr, line->line);
  const std::string plain(plain_qstr.c_str());
  const qstring original = line->line;

  size_t search_from = 0;
  bool changed = false;
  qstring rewritten;
  while ( search_from < plain.size() )
  {
    const size_t arrow = plain.find("->VTABLE[", search_from);
    if ( arrow == std::string::npos )
      break;

    size_t object_start = arrow;
    while ( object_start > search_from
         && is_identifier_char(plain[object_start - 1]) )
    {
      --object_start;
    }
    if ( object_start == arrow || !is_identifier_start(plain[object_start]) )
    {
      search_from = arrow + 2;
      continue;
    }

    const size_t number_start = arrow + 9;
    const size_t token_end = plain.find(']', number_start);
    if ( token_end == std::string::npos )
      break;

    const std::string object =
      plain.substr(object_start, arrow - object_start);
    const std::string number =
      plain.substr(number_start, token_end - number_start);
    if ( number.empty() )
    {
      search_from = token_end + 1;
      continue;
    }

    const char *raw_begin = original.c_str();
    const char *raw_search_from = tag_advance(raw_begin, int(search_from));
    const char *raw_object_start = tag_advance(raw_begin, int(object_start));
    const char object_color_value =
      find_identifier_color(original, object, token_end + 1);
    const char object_color[] = { object_color_value, '\0' };
    rewritten.append(raw_search_from, raw_object_start - raw_search_from);
    append_colored(&rewritten, object.c_str(), object_color);
    append_colored(&rewritten, "->", SCOLOR_SYMBOL);
    append_colored(&rewritten, "VTABLE", SCOLOR_DEFAULT);
    append_colored(&rewritten, "[", SCOLOR_SYMBOL);
    append_colored(&rewritten, number.c_str(), SCOLOR_NUMBER);
    append_colored(&rewritten, "]", SCOLOR_SYMBOL);

    search_from = token_end + 1;
    changed = true;
  }

  if ( changed )
  {
    const char *raw_tail = tag_advance(original.c_str(), int(search_from));
    rewritten.append(raw_tail);
    line->line.swap(rewritten);
  }
  return changed;
}

bool vtable_rewrite_self_test()
{
  simpleline_t line;
  line.line = "return *(*";
  append_colored(&line.line, "a1", SCOLOR_LOCNAME);
  line.line.append(" + ");
  append_colored(&line.line, "0x10", SCOLOR_NUMBER);
  line.line.append(")(a1, 0);");

  vtable_markers_t markers;
  if ( !rewrite_vtable_line(&line, 0, &markers) || markers.size() != 1 )
    return false;
  normalize_vtable_colors(&line);

  qstring plain;
  tag_remove(&plain, line.line);
  if ( plain != "return a1->VTABLE[0x2](a1, 0);" )
    return false;

  const std::string raw(line.line.c_str());
  const std::string colored_object =
    std::string(SCOLOR_ON) + SCOLOR_LIBNAME + "a1"
    + SCOLOR_OFF + SCOLOR_LIBNAME;
  const std::string colored_name =
    std::string(SCOLOR_ON) + SCOLOR_DEFAULT + "VTABLE"
    + SCOLOR_OFF + SCOLOR_DEFAULT;
  const std::string colored_number =
    std::string(SCOLOR_ON) + SCOLOR_NUMBER + "0x2"
    + SCOLOR_OFF + SCOLOR_NUMBER;
  return raw.find(colored_object) != std::string::npos
      && raw.find(colored_name) != std::string::npos
      && raw.find(colored_number) != std::string::npos
      && markers[0].byte_offset == 0x10
      && markers[0].slot == 2;
}

struct xref_entry_t
{
  ea_t from = BADADDR;
  uchar type = 0;
};

using xref_entries_t = qvector<xref_entry_t>;

struct xref_popup_t final : chooser_t
{
  static const int widths[];
  static const char *const headers[];

  ea_t target;
  const xref_entries_t &entries;

  xref_popup_t(ea_t target_, const xref_entries_t &entries_, const char *title_)
    : chooser_t(
        CH_MODAL | CH_KEEP,
        4,
        widths,
        headers,
        title_),
      target(target_),
      entries(entries_)
  {
    deflt_col = 2;
  }

  size_t idaapi get_count() const override
  {
    return entries.size();
  }

  ea_t idaapi get_ea(size_t n) const override
  {
    return entries[n].from;
  }

  void idaapi get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const override
  {
    const xref_entry_t &entry = entries[n];
    qstrvec_t &cols = *cols_;
    cols[0] = entry.from < target ? "Up" : entry.from > target ? "Down" : "";
    cols[1].sprnt("%c", xrefchar(entry.type));
    cols[2].sprnt("%a", entry.from);
    generate_disasm_line(&cols[3], entry.from, GENDSM_REMOVE_TAGS);
  }
};

const int xref_popup_t::widths[] =
{
  6,
  4,
  CHCOL_HEX | 16,
  60,
};

const char *const xref_popup_t::headers[] =
{
  "Direction",
  "Type",
  "Address",
  "Instruction",
};

bool show_xref_popup(ea_t target)
{
  xref_entries_t entries;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target, XREF_ALL); ok; ok = xb.next_to() )
  {
    xref_entry_t &entry = entries.push_back();
    entry.from = xb.from;
    entry.type = xb.type;
  }

  qstring target_name;
  get_ea_name(&target_name, target);
  if ( target_name.empty() )
    target_name.sprnt("%a", target);

  qstring title;
  title.sprnt("Xrefs to %s", target_name.c_str());
  if ( entries.empty() )
  {
    warning("There are no cross-references to %s", target_name.c_str());
    return false;
  }

  xref_popup_t popup(target, entries, title.c_str());
  const ssize_t selected = popup.choose();
  if ( selected < 0 || selected >= entries.size() )
    return true;

  jumpto(entries[selected].from);
  return true;
}

bool show_xrefs(vdui_t *vu)
{
  if ( vu == nullptr || !vu->get_current_item(USE_KEYBOARD) )
    return false;

  ea_t target = BADADDR;
  if ( vu->item.citype == VDI_FUNC && vu->item.f != nullptr )
  {
    target = vu->item.f->entry_ea;
  }
  else if ( vu->item.is_citem()
         && vu->item.it != nullptr
         && vu->item.it->is_expr()
         && vu->item.e->op == cot_obj )
  {
    target = vu->item.e->obj_ea;
  }

  if ( target != BADADDR )
    return show_xref_popup(target);

  warning("The item under the cursor does not have an addressable xref target");
  return false;
}

struct show_xrefs_action_t final : action_handler_t
{
  int idaapi activate(action_activation_ctx_t *ctx) override
  {
    if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
      return 0;

    return show_xrefs(get_widget_vdui(ctx->widget)) ? 1 : 0;
  }

  action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
         ? AST_ENABLE_FOR_WIDGET
         : AST_DISABLE_FOR_WIDGET;
  }
};

show_xrefs_action_t show_xrefs_action;

ssize_t idaapi decompiler_callback(void *, hexrays_event_t, va_list);

struct pseudocode_xrefs_plugmod_t final : plugmod_t
{
  struct show_vtable_offset_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit show_vtable_offset_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->show_vtable_offset(get_widget_vdui(ctx->widget)) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  qmap<ea_t, vtable_markers_t> vtable_markers;
  show_vtable_offset_action_t show_vtable_offset_action;

  pseudocode_xrefs_plugmod_t()
    : show_vtable_offset_action(this)
  {
    const action_desc_t xref_desc = ACTION_DESC_LITERAL_PLUGMOD(
      ACTION_NAME,
      ACTION_LABEL,
      &show_xrefs_action,
      this,
      ACTION_HOTKEY,
      "Show cross-references to the pseudocode item under the cursor",
      -1);

    if ( !register_action(xref_desc) )
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, ACTION_NAME);

    const action_desc_t vtable_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_ACTION_NAME,
      VTABLE_ACTION_LABEL,
      &show_vtable_offset_action,
      this,
      VTABLE_ACTION_HOTKEY,
      "Show the original byte offset for a synthetic VTABLE slot",
      -1);

    if ( !register_action(vtable_desc) )
      msg(
        "%s: failed to register action %s\n",
        PLUGIN.wanted_name,
        VTABLE_ACTION_NAME);

    if ( !install_hexrays_callback(decompiler_callback, this) )
      msg("%s: failed to install the pseudocode keyboard callback\n", PLUGIN.wanted_name);
  }

  ~pseudocode_xrefs_plugmod_t() override
  {
    remove_hexrays_callback(decompiler_callback, this);
  }

  bool idaapi run(size_t) override
  {
    return false;
  }

  void rewrite_vtable_calls(cfunc_t *cfunc)
  {
    vtable_markers_t &markers = vtable_markers[cfunc->entry_ea];
    markers.clear();
    for ( int line_number = 0; line_number < cfunc->sv.size(); ++line_number )
    {
      rewrite_vtable_line(&cfunc->sv[line_number], line_number, &markers);
      normalize_vtable_colors(&cfunc->sv[line_number]);
    }
  }

  bool show_vtable_offset(vdui_t *vu)
  {
    if ( vu == nullptr || vu->cfunc == nullptr || !vu->refresh_cpos(USE_KEYBOARD) )
      return false;

    const auto found = vtable_markers.find(vu->cfunc->entry_ea);
    if ( found == vtable_markers.end() )
      return false;

    for ( const vtable_marker_t &marker : found->second )
    {
      if ( marker.line == vu->cpos.lnnum
        && vu->cpos.x >= marker.start_column
        && vu->cpos.x < marker.end_column )
      {
        info(
          "VTABLE[0x%" FMT_64 "X] uses original byte offset 0x%" FMT_64 "X",
          uint64(marker.slot),
          uint64(marker.byte_offset));
        return true;
      }
    }

    if ( vu->cpos.lnnum >= 0 && vu->cpos.lnnum < vu->cfunc->sv.size() )
    {
      qstring plain_line;
      tag_remove(&plain_line, vu->cfunc->sv[vu->cpos.lnnum].line);
      const std::string plain(plain_line.c_str());
      size_t token_start = plain.find("VTABLE[");
      while ( token_start != std::string::npos )
      {
        const size_t number_start = token_start + 7;
        const size_t token_end = plain.find(']', number_start);
        if ( token_end == std::string::npos )
          break;

        if ( vu->cpos.x >= int(token_start)
          && vu->cpos.x <= int(token_end) )
        {
          const std::string number =
            plain.substr(number_start, token_end - number_start);
          char *number_end = nullptr;
          const uval_t slot = uval_t(::strtoull(number.c_str(), &number_end, 0));
          if ( number_end != number.c_str() && *number_end == '\0' )
          {
            const uval_t byte_offset = slot * (inf_is_64bit() ? 8 : 4);
            info(
              "VTABLE[0x%" FMT_64 "X] uses original byte offset 0x%" FMT_64 "X",
              uint64(slot),
              uint64(byte_offset));
            return true;
          }
        }
        token_start = plain.find("VTABLE[", token_end + 1);
      }
    }

    warning("Place the cursor on a VTABLE[...] token and press J");
    return false;
  }

  const vtable_marker_t *find_vtable_marker(vdui_t *vu)
  {
    if ( vu == nullptr || vu->cfunc == nullptr || !vu->refresh_cpos(USE_MOUSE) )
      return nullptr;

    const auto found = vtable_markers.find(vu->cfunc->entry_ea);
    if ( found == vtable_markers.end() )
      return nullptr;

    for ( const vtable_marker_t &marker : found->second )
    {
      if ( marker.line == vu->cpos.lnnum
        && vu->cpos.x >= marker.start_column
        && vu->cpos.x < marker.end_column )
      {
        return &marker;
      }
    }
    return nullptr;
  }

  bool jump_to_vtable_target(vdui_t *vu)
  {
    const vtable_marker_t *marker = find_vtable_marker(vu);
    if ( marker == nullptr )
      return false;

    const lvars_t *lvars = vu->cfunc->get_lvars();
    const lvar_t *object_lvar = nullptr;
    for ( const lvar_t &lvar : *lvars )
    {
      if ( lvar.name == marker->object_name )
      {
        object_lvar = &lvar;
        break;
      }
    }
    if ( object_lvar == nullptr )
    {
      warning("Could not find the variable '%s'", marker->object_name.c_str());
      return true;
    }

    tinfo_t object_type = object_lvar->type();
    if ( !object_type.is_ptr() || !object_type.remove_ptr_or_array() )
    {
      warning(
        "Variable '%s' is not typed as a pointer to a class",
        marker->object_name.c_str());
      return true;
    }

    qstring class_name;
    if ( !object_type.get_type_name(&class_name)
      && !object_type.get_final_type_name(&class_name) )
    {
      warning(
        "Could not determine the class type of '%s'",
        marker->object_name.c_str());
      return true;
    }

    qstring vtable_name = class_name;
    vtable_name.append("_vft");
    ea_t vtable_ea = get_name_ea(BADADDR, vtable_name.c_str());
    if ( vtable_ea == BADADDR )
    {
      const char *separator = strrchr(class_name.c_str(), ':');
      if ( separator != nullptr )
      {
        vtable_name = separator + 1;
        vtable_name.append("_vft");
        vtable_ea = get_name_ea(BADADDR, vtable_name.c_str());
      }
    }
    if ( vtable_ea == BADADDR )
    {
      warning("Could not find vtable symbol '%s'", vtable_name.c_str());
      return true;
    }

    const size_t pointer_size = inf_is_64bit() ? 8 : 4;
    const ea_t entry_ea = vtable_ea + marker->slot * pointer_size;
    if ( !is_loaded(entry_ea) )
    {
      warning(
        "VTABLE slot 0x%" FMT_64 "X is not loaded at %a",
        uint64(marker->slot),
        entry_ea);
      return true;
    }

    const ea_t target =
      pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
    if ( target == BADADDR || !is_mapped(target) )
    {
      warning(
        "VTABLE slot 0x%" FMT_64 "X does not contain a mapped function address",
        uint64(marker->slot));
      return true;
    }

    jumpto(target);
    return true;
  }
};

ssize_t idaapi decompiler_callback(
        void *user_data,
        hexrays_event_t event,
        va_list va)
{
  auto *plugin = static_cast<pseudocode_xrefs_plugmod_t *>(user_data);
  if ( event == hxe_func_printed )
  {
    plugin->rewrite_vtable_calls(va_arg(va, cfunc_t *));
    return 0;
  }

  if ( event == hxe_double_click )
  {
    vdui_t *vu = va_arg(va, vdui_t *);
    const int shift_state = va_arg(va, int);
    return shift_state == 0 && plugin->jump_to_vtable_target(vu) ? 1 : 0;
  }

  if ( event != hxe_keyboard )
    return 0;

  vdui_t *vu = va_arg(va, vdui_t *);
  const int key_code = va_arg(va, int);
  const int shift_state = va_arg(va, int);
  if ( shift_state != 0 )
    return 0;

  if ( key_code == 'K' || key_code == 'k' )
  {
    show_xrefs(vu);
    return 1;
  }
  if ( key_code == 'J' || key_code == 'j' )
  {
    plugin->show_vtable_offset(vu);
    return 1;
  }
  return 0;
}

plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr;
  if ( !vtable_rewrite_self_test() )
  {
    warning("Pseudocode Xrefs: internal VTABLE rewrite test failed");
    return nullptr;
  }
  return new pseudocode_xrefs_plugmod_t;
}

} // namespace

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "Shows xrefs for the pseudocode item under the cursor.",
  "",
  "Pseudocode Xrefs",
  ""
};
