#include <hexrays.hpp>
#include <xref.hpp>
#include <diskio.hpp>
#include <fpro.h>
#include <netnode.hpp>

#include <cctype>
#include <cstdlib>
#include <string>

#ifdef __NT__
#include <windows.h>
#endif

namespace
{

constexpr char ACTION_NAME[] = "pseudocode_xrefs:show";
constexpr char ACTION_LABEL[] = "Show xrefs to item";
constexpr char ACTION_HOTKEY[] = "K";
constexpr char VTABLE_ACTION_NAME[] = "pseudocode_xrefs:jump_vtable_target";
constexpr char VTABLE_ACTION_LABEL[] = "Jump to VTABLE target";
constexpr char VTABLE_ACTION_HOTKEY[] = "J";
constexpr char VTABLE_INDEX_ACTION_NAME[] = "pseudocode_xrefs:show_vtable_index";
constexpr char VTABLE_INDEX_ACTION_LABEL[] = "Show VTABLE index";
constexpr char VTABLE_INDEX_ACTION_HOTKEY[] = "I";
constexpr char VTABLE_RENAME_ACTION_NAME[] = "pseudocode_xrefs:rename_vtable_target";
constexpr char VTABLE_RENAME_ACTION_LABEL[] = "Rename VTABLE target";
constexpr char VTABLE_XREF_ACTION_NAME[] = "pseudocode_xrefs:show_hierarchy_versions";
constexpr char VTABLE_XREF_ACTION_LABEL[] = "Show hierarchy implementations";
constexpr char VTABLE_DECLARING_ACTION_NAME[] = "pseudocode_xrefs:set_declaring_class";
constexpr char VTABLE_DECLARING_ACTION_LABEL[] = "Set virtual method declaring class...";
constexpr char DECLARATIONS_NODE_NAME[] = "$ pseudocode_xrefs declarations";

struct vtable_marker_t
{
  int line = -1;
  int start_column = 0;
  int end_column = 0;
  uval_t byte_offset = 0;
  uval_t slot = 0;
  qstring object_name;
  ea_t target = BADADDR;
  qstring display_name;
};

using vtable_markers_t = qvector<vtable_marker_t>;

bool is_identifier_char(char c);

bool find_class_vtable(
      const qstring &class_name,
      qstring *vtable_name,
      ea_t *vtable_ea)
{
  qvector<qstring> class_candidates;
  class_candidates.push_back(class_name);
  const char *separator = strrchr(class_name.c_str(), ':');
  if ( separator != nullptr )
    class_candidates.push_back(separator + 1);

  constexpr const char *suffixes[] = { "_vft", "_Vft", "_VFT" };
  for ( const qstring &candidate : class_candidates )
  {
    for ( const char *suffix : suffixes )
    {
      *vtable_name = candidate;
      vtable_name->append(suffix);
      *vtable_ea = get_name_ea(BADADDR, vtable_name->c_str());
      if ( *vtable_ea != BADADDR )
        return true;
    }
  }
  return false;
}

bool find_object_vtable(
      cfunc_t *cfunc,
      const qstring &object_name,
      qstring *class_name,
      qstring *vtable_name,
      ea_t *vtable_ea)
{
  const lvars_t *lvars = cfunc->get_lvars();
  const lvar_t *object_lvar = nullptr;
  for ( const lvar_t &lvar : *lvars )
  {
    if ( lvar.name == object_name )
    {
      object_lvar = &lvar;
      break;
    }
  }
  if ( object_lvar == nullptr )
    return false;

  tinfo_t object_type = object_lvar->type();
  if ( !object_type.is_ptr() || !object_type.remove_ptr_or_array() )
    return false;
  if ( !object_type.get_type_name(class_name)
    && !object_type.get_final_type_name(class_name) )
  {
    return false;
  }

  return find_class_vtable(*class_name, vtable_name, vtable_ea);
}

bool get_vtable_entry_target(
      cfunc_t *cfunc,
      const vtable_marker_t &marker,
      ea_t *target)
{
  qstring class_name;
  qstring vtable_name;
  ea_t vtable_ea = BADADDR;
  if ( !find_object_vtable(
        cfunc,
        marker.object_name,
        &class_name,
        &vtable_name,
        &vtable_ea) )
  {
    return false;
  }

  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  const ea_t entry_ea = vtable_ea + marker.slot * pointer_size;
  if ( !is_loaded(entry_ea) )
    return false;
  *target =
    pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
  return *target != BADADDR && is_mapped(*target);
}

bool get_named_vtable_entry(
      cfunc_t *cfunc,
      vtable_marker_t *marker)
{
  ea_t target = BADADDR;
  if ( !get_vtable_entry_target(cfunc, *marker, &target) )
    return false;

  qstring short_name = get_short_name(target);
  std::string display(short_name.c_str());
  const size_t namespace_separator = display.rfind("::");
  if ( namespace_separator != std::string::npos )
    display.erase(0, namespace_separator + 2);
  if ( display.empty() || display.rfind("sub_", 0) == 0 )
    return false;

  marker->target = target;
  marker->display_name = display.c_str();
  return true;
}

struct inheritance_edge_t
{
  qstring derived;
  qstring base;
};

using inheritance_edges_t = qvector<inheritance_edge_t>;

bool contains_type_name(const qvector<qstring> &names, const qstring &name)
{
  for ( const qstring &candidate : names )
  {
    if ( candidate == name )
      return true;
  }
  return false;
}

void collect_inheritance_edges(inheritance_edges_t *edges)
{
  const uint32 ordinal_limit = get_ordinal_limit(nullptr);
  for ( uint32 ordinal = 1; ordinal < ordinal_limit; ++ordinal )
  {
    const char *derived_name = get_numbered_type_name(nullptr, ordinal);
    if ( derived_name == nullptr || *derived_name == '\0' )
      continue;

    tinfo_t derived_type;
    if ( !derived_type.get_numbered_type(ordinal) )
      continue;
    udt_type_data_t udt;
    if ( !derived_type.get_udt_details(&udt) )
      continue;

    for ( const udm_t &member : udt )
    {
      if ( !member.is_baseclass() )
        continue;
      qstring base_name;
      if ( !member.type.get_type_name(&base_name)
        && !member.type.get_final_type_name(&base_name) )
      {
        continue;
      }
      inheritance_edge_t &edge = edges->push_back();
      edge.derived = derived_name;
      edge.base = base_name;
    }
  }
}

void collect_connected_hierarchy(
      const qstring &selected_class,
      qvector<qstring> *class_names)
{
  class_names->push_back(selected_class);
  inheritance_edges_t edges;
  collect_inheritance_edges(&edges);

  bool changed = true;
  while ( changed )
  {
    changed = false;
    for ( const inheritance_edge_t &edge : edges )
    {
      const bool has_derived = contains_type_name(*class_names, edge.derived);
      const bool has_base = contains_type_name(*class_names, edge.base);
      if ( has_derived && !has_base )
      {
        class_names->push_back(edge.base);
        changed = true;
      }
      else if ( has_base && !has_derived )
      {
        class_names->push_back(edge.derived);
        changed = true;
      }
    }
  }
}

void collect_class_lineage(
      const qstring &selected_class,
      qvector<qstring> *class_names)
{
  inheritance_edges_t edges;
  collect_inheritance_edges(&edges);
  class_names->push_back(selected_class);

  qvector<qstring> ancestors;
  ancestors.push_back(selected_class);
  for ( size_t cursor = 0; cursor < ancestors.size(); ++cursor )
  {
    for ( const inheritance_edge_t &edge : edges )
    {
      if ( edge.derived == ancestors[cursor]
        && !contains_type_name(ancestors, edge.base) )
      {
        ancestors.push_back(edge.base);
        if ( !contains_type_name(*class_names, edge.base) )
          class_names->push_back(edge.base);
      }
    }
  }

  qvector<qstring> descendants;
  descendants.push_back(selected_class);
  for ( size_t cursor = 0; cursor < descendants.size(); ++cursor )
  {
    for ( const inheritance_edge_t &edge : edges )
    {
      if ( edge.base == descendants[cursor]
        && !contains_type_name(descendants, edge.derived) )
      {
        descendants.push_back(edge.derived);
        if ( !contains_type_name(*class_names, edge.derived) )
          class_names->push_back(edge.derived);
      }
    }
  }
}

void collect_descendant_hierarchy(
      const qstring &declaring_class,
      qvector<qstring> *class_names)
{
  inheritance_edges_t edges;
  collect_inheritance_edges(&edges);
  class_names->push_back(declaring_class);
  for ( size_t cursor = 0; cursor < class_names->size(); ++cursor )
  {
    for ( const inheritance_edge_t &edge : edges )
    {
      if ( edge.base == (*class_names)[cursor]
        && !contains_type_name(*class_names, edge.derived) )
      {
        class_names->push_back(edge.derived);
      }
    }
  }
}

void collect_ancestor_hierarchy(
      const qstring &selected_class,
      qvector<qstring> *class_names)
{
  inheritance_edges_t edges;
  collect_inheritance_edges(&edges);
  class_names->push_back(selected_class);
  for ( size_t cursor = 0; cursor < class_names->size(); ++cursor )
  {
    for ( const inheritance_edge_t &edge : edges )
    {
      if ( edge.derived == (*class_names)[cursor]
        && !contains_type_name(*class_names, edge.base) )
      {
        class_names->push_back(edge.base);
      }
    }
  }
}

ea_t get_class_vtable_entry(const qstring &class_name, uval_t slot)
{
  qstring vtable_name;
  ea_t vtable_ea = BADADDR;
  if ( !find_class_vtable(class_name, &vtable_name, &vtable_ea) )
    return BADADDR;
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  const ea_t entry_ea = vtable_ea + slot * pointer_size;
  return is_loaded(entry_ea) ? entry_ea : BADADDR;
}

bool get_declaring_class(
      const qstring &selected_class,
      uval_t slot,
      qstring *declaring_class)
{
  netnode declarations(DECLARATIONS_NODE_NAME);
  qvector<qstring> ancestors;
  collect_ancestor_hierarchy(selected_class, &ancestors);
  for ( const qstring &candidate : ancestors )
  {
    const ea_t entry_ea = get_class_vtable_entry(candidate, slot);
    if ( entry_ea != BADADDR
      && declarations.supstr_ea(declaring_class, entry_ea) > 0 )
    {
      return true;
    }
  }
  return false;
}

bool set_declaring_class_metadata(
      const qstring &selected_class,
      const qstring &declaring_class,
      uval_t slot)
{
  netnode declarations;
  declarations.create(DECLARATIONS_NODE_NAME);

  qvector<qstring> connected;
  collect_connected_hierarchy(selected_class, &connected);
  for ( const qstring &class_name : connected )
  {
    const ea_t entry_ea = get_class_vtable_entry(class_name, slot);
    if ( entry_ea != BADADDR )
      declarations.supdel_ea(entry_ea);
  }

  const ea_t declaring_entry = get_class_vtable_entry(declaring_class, slot);
  return declaring_entry != BADADDR
      && declarations.supset_ea(declaring_entry, declaring_class.c_str());
}

qstring identifier_from_type_name(const qstring &type_name)
{
  qstring result;
  for ( const char *cursor = type_name.c_str(); *cursor != '\0'; ++cursor )
  {
    const char c = *cursor;
    result.append(is_identifier_char(c) ? c : '_');
  }
  return result;
}

struct hierarchy_target_t
{
  qstring class_name;
  qstring vtable_name;
  ea_t vtable_ea = BADADDR;
  ea_t target = BADADDR;
};

using hierarchy_targets_t = qvector<hierarchy_target_t>;

void collect_hierarchy_targets(
      const qstring &selected_class,
      uval_t slot,
      hierarchy_targets_t *targets,
      size_t *vtable_count)
{
  qvector<qstring> class_names;
  qstring declaring_class;
  if ( get_declaring_class(selected_class, slot, &declaring_class) )
    collect_descendant_hierarchy(declaring_class, &class_names);
  else
    collect_descendant_hierarchy(selected_class, &class_names);
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  *vtable_count = 0;
  for ( const qstring &class_name : class_names )
  {
    qstring vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_class_vtable(class_name, &vtable_name, &vtable_ea) )
      continue;
    ++*vtable_count;

    const ea_t entry_ea = vtable_ea + slot * pointer_size;
    if ( !is_loaded(entry_ea) )
      continue;
    const ea_t target =
      pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
    if ( target == BADADDR || !is_mapped(target) )
      continue;

    bool duplicate = false;
    for ( const hierarchy_target_t &existing : *targets )
    {
      if ( existing.target == target )
      {
        duplicate = true;
        break;
      }
    }
    if ( duplicate )
      continue;

    hierarchy_target_t &entry = targets->push_back();
    entry.class_name = class_name;
    entry.vtable_name = vtable_name;
    entry.vtable_ea = vtable_ea;
    entry.target = target;
  }
}

void collect_all_hierarchy_targets(
      const qstring &selected_class,
      uval_t slot,
      hierarchy_targets_t *targets)
{
  qvector<qstring> class_names;
  qstring declaring_class;
  if ( get_declaring_class(selected_class, slot, &declaring_class) )
    collect_descendant_hierarchy(declaring_class, &class_names);
  else
    collect_descendant_hierarchy(selected_class, &class_names);
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  for ( const qstring &class_name : class_names )
  {
    qstring vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_class_vtable(class_name, &vtable_name, &vtable_ea) )
      continue;
    const ea_t entry_ea = vtable_ea + slot * pointer_size;
    if ( !is_loaded(entry_ea) )
      continue;
    const ea_t target =
      pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
    if ( target == BADADDR || !is_mapped(target) )
      continue;
    hierarchy_target_t &entry = targets->push_back();
    entry.class_name = class_name;
    entry.vtable_name = vtable_name;
    entry.vtable_ea = vtable_ea;
    entry.target = target;
  }
}

void debug_log(const char *format, ...)
{
  qstring path;
  path.sprnt("%s/pseudocode_xrefs.log", get_user_idadir());
  FILE *file = qfopen(path.c_str(), "a");
  if ( file == nullptr )
    return;

  qstring message;
  va_list args;
  va_start(args, format);
  message.vsprnt(format, args);
  va_end(args);
  qfprintf(
    file,
    "[%u.%06u] %s\n",
    get_secs(qtime64()),
    get_usecs(qtime64()),
    message.c_str());
  qfclose(file);
}

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

  // Typed objects are commonly rendered as
  //   (*(object->VTable + slot))(arguments)
  // where pointer arithmetic already uses a slot index rather than a byte offset.
  marker = plain.find("(*(", search_from);
  while ( marker != std::string::npos )
  {
    size_t cursor = marker + 3;
    if ( cursor < plain.size() && is_identifier_start(plain[cursor]) )
    {
      const size_t object_begin = cursor++;
      while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
        ++cursor;
      const size_t object_finish = cursor;
      if ( cursor + 2 <= plain.size() && plain.compare(cursor, 2, "->") == 0 )
      {
        cursor += 2;
        const size_t member_begin = cursor;
        while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
          ++cursor;
        std::string member = plain.substr(member_begin, cursor - member_begin);
        for ( char &c : member )
          c = char(std::tolower(uchar(c)));
        while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
          ++cursor;
        if ( (member == "vtable" || member == "vftable")
          && cursor < plain.size()
          && plain[cursor++] == '+' )
        {
          while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
            ++cursor;
          const size_t number_begin = cursor;
          if ( cursor + 2 <= plain.size()
            && plain[cursor] == '0'
            && (plain[cursor + 1] == 'x' || plain[cursor + 1] == 'X') )
          {
            cursor += 2;
            while ( cursor < plain.size()
                 && std::isxdigit(uchar(plain[cursor])) != 0 )
            {
              ++cursor;
            }
          }
          else
          {
            while ( cursor < plain.size()
                 && std::isdigit(uchar(plain[cursor])) != 0 )
            {
              ++cursor;
            }
          }
          if ( cursor > number_begin )
          {
            const std::string number =
              plain.substr(number_begin, cursor - number_begin);
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
            if ( cursor + 2 < plain.size()
              && plain[cursor] == ')'
              && plain[cursor + 1] == ')'
              && plain[cursor + 2] == '(' )
            {
              const uval_t slot =
                uval_t(::strtoull(number.c_str(), nullptr, 0));
              *match_start = marker;
              *match_end = cursor + 2;
              *object_start = object_begin;
              *object_end = object_finish;
              *byte_offset = slot * (inf_is_64bit() ? 8 : 4);
              return true;
            }
          }
        }
      }
    }
    marker = plain.find("(*(", marker + 3);
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

void collect_rendered_vtable_markers(
      const simpleline_t &line,
      int line_number,
      vtable_markers_t *markers)
{
  qstring plain_qstr;
  tag_remove(&plain_qstr, line.line);
  const std::string plain(plain_qstr.c_str());
  size_t token_start = plain.find("VTABLE[");
  while ( token_start != std::string::npos )
  {
    const size_t number_start = token_start + 7;
    const size_t token_end = plain.find(']', number_start);
    if ( token_end == std::string::npos )
      break;

    if ( token_start >= 2 && plain.compare(token_start - 2, 2, "->") == 0 )
    {
      size_t object_start = token_start - 2;
      while ( object_start > 0 && is_identifier_char(plain[object_start - 1]) )
        --object_start;

      const std::string number =
        plain.substr(number_start, token_end - number_start);
      char *number_end = nullptr;
      const uval_t slot = uval_t(::strtoull(number.c_str(), &number_end, 0));
      if ( object_start < token_start - 2
        && is_identifier_start(plain[object_start])
        && number_end != number.c_str()
        && *number_end == '\0' )
      {
        bool duplicate = false;
        for ( const vtable_marker_t &existing : *markers )
        {
          if ( existing.line == line_number
            && existing.start_column == int(token_start) )
          {
            duplicate = true;
            break;
          }
        }
        if ( !duplicate )
        {
          vtable_marker_t &marker = markers->push_back();
          marker.line = line_number;
          marker.start_column = int(token_start);
          marker.end_column = int(token_end + 1);
          marker.slot = slot;
          marker.byte_offset = slot * (inf_is_64bit() ? 8 : 4);
          marker.object_name =
            plain.substr(object_start, token_start - 2 - object_start).c_str();
        }
      }
    }
    token_start = plain.find("VTABLE[", token_end + 1);
  }
}

void apply_named_vtable_tokens(cfunc_t *cfunc, vtable_markers_t *markers)
{
  for ( vtable_marker_t &marker : *markers )
    get_named_vtable_entry(cfunc, &marker);

  for ( int line_number = 0; line_number < cfunc->sv.size(); ++line_number )
  {
    qvector<vtable_marker_t *> line_markers;
    for ( vtable_marker_t &marker : *markers )
    {
      if ( marker.line == line_number && !marker.display_name.empty() )
        line_markers.push_back(&marker);
    }
    if ( line_markers.empty() )
      continue;

    simpleline_t &line = cfunc->sv[line_number];
    const qstring original = line.line;
    qstring rewritten;
    int previous_column = 0;
    int column_delta = 0;
    for ( vtable_marker_t *marker : line_markers )
    {
      const int old_start = marker->start_column;
      const int old_end = marker->end_column;
      const char *raw_previous = tag_advance(original.c_str(), previous_column);
      const char *raw_start = tag_advance(original.c_str(), old_start);
      rewritten.append(raw_previous, raw_start - raw_previous);
      append_colored(&rewritten, marker->display_name.c_str(), SCOLOR_CODNAME);

      marker->start_column = old_start + column_delta;
      marker->end_column = marker->start_column + int(marker->display_name.length());
      column_delta += int(marker->display_name.length()) - (old_end - old_start);
      previous_column = old_end;
    }
    rewritten.append(tag_advance(original.c_str(), previous_column));
    line.line.swap(rewritten);
  }
}

void collect_named_vtable_markers(cfunc_t *cfunc, vtable_markers_t *markers)
{
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  const lvars_t *lvars = cfunc->get_lvars();
  for ( const lvar_t &lvar : *lvars )
  {
    qstring class_name;
    qstring vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_object_vtable(
          cfunc,
          lvar.name,
          &class_name,
          &vtable_name,
          &vtable_ea) )
    {
      continue;
    }

    size_t slot_count = size_t(get_item_size(vtable_ea)) / pointer_size;
    if ( slot_count <= 1 )
      slot_count = 64;
    for ( size_t slot = 0; slot < slot_count; ++slot )
    {
      vtable_marker_t candidate;
      candidate.object_name = lvar.name;
      candidate.slot = slot;
      candidate.byte_offset = slot * pointer_size;
      if ( !get_named_vtable_entry(cfunc, &candidate) )
      {
        if ( get_item_size(vtable_ea) <= pointer_size )
          break;
        continue;
      }

      const std::string pattern =
        std::string(lvar.name.c_str()) + "->" + candidate.display_name.c_str();
      for ( int line_number = 0; line_number < cfunc->sv.size(); ++line_number )
      {
        qstring plain_qstr;
        tag_remove(&plain_qstr, cfunc->sv[line_number].line);
        const std::string plain(plain_qstr.c_str());
        size_t token_start = plain.find(pattern);
        while ( token_start != std::string::npos )
        {
          const size_t method_start = token_start + lvar.name.length() + 2;
          const size_t method_end = method_start + candidate.display_name.length();
          if ( method_end < plain.size() && plain[method_end] == '(' )
          {
            candidate.line = line_number;
            candidate.start_column = int(method_start);
            candidate.end_column = int(method_end);
            markers->push_back(candidate);
            break;
          }
          token_start = plain.find(pattern, token_start + pattern.length());
        }
      }
    }
  }
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

void jump_to_disassembly(ea_t target)
{
  TWidget *disassembly = find_widget("IDA View-A");
  if ( disassembly == nullptr )
    disassembly = open_disasm_window("IDA View-A");
  if ( disassembly != nullptr )
    activate_widget(disassembly, true);
  jumpto(target);
}

struct hierarchy_popup_t final : chooser_t
{
  static const int widths[];
  static const char *const headers[];
  const hierarchy_targets_t &entries;
  mutable int activated_column = 2;

  hierarchy_popup_t(const hierarchy_targets_t &entries_, const char *title_)
    : chooser_t(CH_MODAL | CH_KEEP, 4, widths, headers, title_), entries(entries_)
  {
    deflt_col = 0;
  }

  size_t idaapi get_count() const override { return entries.size(); }
  ea_t idaapi get_ea(size_t) const override { return BADADDR; }

  cbret_t idaapi enter(size_t n) override
  {
    activated_column = 2;
#ifdef __NT__
    if ( (GetKeyState(VK_RETURN) & 0x8000) == 0 )
    {
      HWND window = GetForegroundWindow();
      POINT cursor;
      RECT client;
      if ( window != nullptr
        && GetCursorPos(&cursor)
        && ScreenToClient(window, &cursor)
        && GetClientRect(window, &client)
        && client.right > client.left )
      {
        UINT dpi = GetDpiForWindow(window);
        if ( dpi == 0 )
          dpi = 96;
        const int char_width = MulDiv(9, int(dpi), 96);
        const int base_padding = MulDiv(14, int(dpi), 96);
        const int separator_padding = MulDiv(5, int(dpi), 96);
        const int class_end = 24 * char_width + base_padding;
        const int vtable_end = (24 + 28) * char_width
                             + base_padding + separator_padding;
        const int implementation_end = (24 + 28 + 40) * char_width
                                      + base_padding + 2 * separator_padding;
        activated_column = cursor.x < class_end ? 0
                         : cursor.x < vtable_end ? 1
                         : cursor.x < implementation_end ? 2
                         : 3;
      }
    }
#endif
    return chooser_t::enter(n);
  }

  void idaapi get_row(
        qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const override
  {
    const hierarchy_target_t &entry = entries[n];
    qstrvec_t &cols = *cols_;
    cols[0] = entry.class_name;
    cols[1] = entry.vtable_name;
    cols[2] = get_short_name(entry.target);
    cols[3].sprnt("%a", entry.target);
  }
};

const int hierarchy_popup_t::widths[] = { 24, 28, 40, CHCOL_HEX | 16 };
const char *const hierarchy_popup_t::headers[] =
  { "Class", "VTABLE", "Implementation", "Address" };

struct declaring_class_popup_t final : chooser_t
{
  static const int widths[];
  static const char *const headers[];
  const qvector<qstring> &classes;

  declaring_class_popup_t(const qvector<qstring> &classes_, const char *title_)
    : chooser_t(CH_MODAL | CH_KEEP, 1, widths, headers, title_), classes(classes_)
  {
  }

  size_t idaapi get_count() const override { return classes.size(); }

  void idaapi get_row(
        qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const override
  {
    (*cols_)[0] = classes[n];
  }
};

const int declaring_class_popup_t::widths[] = { 40 };
const char *const declaring_class_popup_t::headers[] = { "First declaring class" };

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
  struct ui_listener_t final : event_listener_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit ui_listener_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
      if ( code != ui_preprocess_action )
        return 0;
      const char *action_name = va_arg(va, const char *);
      if ( action_name == nullptr )
        return 0;

      TWidget *widget = get_current_widget();
      if ( widget == nullptr || get_widget_type(widget) != BWN_PSEUDOCODE )
        return 0;
      vdui_t *vu = get_widget_vdui(widget);
      if ( strcmp(action_name, "hx:Rename") == 0 )
        return plugin->rename_vtable_target(vu) ? 1 : 0;
      return 0;
    }
  };

  struct view_listener_t final : event_listener_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit view_listener_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
      TWidget *view = va_arg(va, TWidget *);
      if ( view == nullptr || get_widget_type(view) != BWN_PSEUDOCODE )
        return 0;

      if ( code == view_keydown )
      {
        const int key_code = va_arg(va, int);
        const int state = va_arg(va, int);
        if ( state == 0 && (key_code == 'N' || key_code == 'n') )
        {
          debug_log("view key N: view=%p", view);
          return plugin->rename_vtable_target(get_widget_vdui(view)) ? 1 : 0;
        }
        return 0;
      }

      if ( code != view_dblclick )
        return 0;

      const view_mouse_event_t *event = va_arg(va, const view_mouse_event_t *);

      debug_log(
        "view double click: view=%p screen=(%u,%u) renderer=(%d,%d)",
        view,
        event != nullptr ? event->x : 0,
        event != nullptr ? event->y : 0,
        event != nullptr ? event->renderer_pos.cx : -1,
        event != nullptr ? event->renderer_pos.cy : -1);
      return plugin->jump_to_vtable_target(
        get_widget_vdui(view),
        USE_MOUSE,
        false) ? 1 : 0;
    }
  };

  struct jump_vtable_target_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit jump_vtable_target_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->jump_to_vtable_target(
        get_widget_vdui(ctx->widget),
        USE_KEYBOARD,
        true) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct show_vtable_index_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit show_vtable_index_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->show_vtable_index(get_widget_vdui(ctx->widget)) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct rename_vtable_target_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit rename_vtable_target_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->rename_vtable_target(get_widget_vdui(ctx->widget)) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return AST_DISABLE_FOR_WIDGET;
      vtable_marker_t fallback;
      return plugin->find_vtable_marker(
               get_widget_vdui(ctx->widget),
               USE_KEYBOARD,
               &fallback) != nullptr
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct hierarchy_xrefs_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit hierarchy_xrefs_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx != nullptr
        && ctx->widget_type == BWN_PSEUDOCODE
        && plugin->show_hierarchy_versions(get_widget_vdui(ctx->widget)) )
      {
        return 1;
      }
      return process_ui_action("hx:JmpXref") ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct set_declaring_class_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit set_declaring_class_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->set_declaring_class(get_widget_vdui(ctx->widget)) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  qmap<ea_t, vtable_markers_t> vtable_markers;
  ui_listener_t ui_listener;
  view_listener_t view_listener;
  jump_vtable_target_action_t jump_vtable_target_action;
  show_vtable_index_action_t show_vtable_index_action;
  rename_vtable_target_action_t rename_vtable_target_action;
  hierarchy_xrefs_action_t hierarchy_xrefs_action;
  set_declaring_class_action_t set_declaring_class_action;
  qstring native_xref_shortcut;

  pseudocode_xrefs_plugmod_t()
    : ui_listener(this),
      view_listener(this),
      jump_vtable_target_action(this),
      show_vtable_index_action(this),
      rename_vtable_target_action(this),
      hierarchy_xrefs_action(this),
      set_declaring_class_action(this)
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
      &jump_vtable_target_action,
      this,
      VTABLE_ACTION_HOTKEY,
      "Jump through a typed object's matching class vtable",
      -1);

    if ( !register_action(vtable_desc) )
      msg(
        "%s: failed to register action %s\n",
        PLUGIN.wanted_name,
        VTABLE_ACTION_NAME);

    const action_desc_t index_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_INDEX_ACTION_NAME,
      VTABLE_INDEX_ACTION_LABEL,
      &show_vtable_index_action,
      this,
      VTABLE_INDEX_ACTION_HOTKEY,
      "Show the selected virtual method's vtable index and byte offset",
      -1);
    if ( !register_action(index_desc) )
      msg(
        "%s: failed to register action %s\n",
        PLUGIN.wanted_name,
        VTABLE_INDEX_ACTION_NAME);

    const action_desc_t rename_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_RENAME_ACTION_NAME,
      VTABLE_RENAME_ACTION_LABEL,
      &rename_vtable_target_action,
      this,
      nullptr,
      "Rename the function stored in the selected vtable slot",
      -1);
    if ( !register_action(rename_desc) )
      msg(
        "%s: failed to register action %s\n",
        PLUGIN.wanted_name,
        VTABLE_RENAME_ACTION_NAME);

    get_action_shortcut(&native_xref_shortcut, "hx:JmpXref");
    update_action_shortcut("hx:JmpXref", nullptr);
    const action_desc_t hierarchy_xref_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_XREF_ACTION_NAME,
      VTABLE_XREF_ACTION_LABEL,
      &hierarchy_xrefs_action,
      this,
      "X",
      "Show all implementations at this hierarchy VTABLE slot; otherwise use native xrefs",
      -1);
    if ( !register_action(hierarchy_xref_desc) )
    {
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, VTABLE_XREF_ACTION_NAME);
      update_action_shortcut("hx:JmpXref", native_xref_shortcut.c_str());
      native_xref_shortcut.clear();
    }

    const action_desc_t declaring_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_DECLARING_ACTION_NAME,
      VTABLE_DECLARING_ACTION_LABEL,
      &set_declaring_class_action,
      this,
      nullptr,
      "Set the first class that declares this virtual method slot",
      -1);
    if ( !register_action(declaring_desc) )
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, VTABLE_DECLARING_ACTION_NAME);

    if ( !install_hexrays_callback(decompiler_callback, this) )
      msg("%s: failed to install the pseudocode keyboard callback\n", PLUGIN.wanted_name);
    if ( !hook_event_listener(HT_VIEW, &view_listener) )
      msg("%s: failed to install the pseudocode mouse callback\n", PLUGIN.wanted_name);
    if ( !hook_event_listener(HT_UI, &ui_listener) )
      msg("%s: failed to install the pseudocode rename callback\n", PLUGIN.wanted_name);
    debug_log("plugin initialized: version=1.7.1");
  }

  ~pseudocode_xrefs_plugmod_t() override
  {
    if ( !native_xref_shortcut.empty() )
      update_action_shortcut("hx:JmpXref", native_xref_shortcut.c_str());
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
      collect_rendered_vtable_markers(
        cfunc->sv[line_number],
        line_number,
        &markers);
    }
    if ( markers.empty() )
      collect_named_vtable_markers(cfunc, &markers);
    else
      apply_named_vtable_tokens(cfunc, &markers);
    debug_log(
      "func_printed: function=%a markers=%" FMT_Z,
      cfunc->entry_ea,
      markers.size());
  }

  bool parse_rendered_vtable_marker(
        vdui_t *vu,
        vtable_marker_t *marker,
        bool allow_sole_token)
  {
    if ( vu->cpos.lnnum < 0 || vu->cpos.lnnum >= vu->cfunc->sv.size() )
      return false;

    qstring plain_line;
    tag_remove(&plain_line, vu->cfunc->sv[vu->cpos.lnnum].line);
    const std::string plain(plain_line.c_str());
    vtable_marker_t sole_marker;
    size_t valid_token_count = 0;
    size_t token_start = plain.find("VTABLE[");
    while ( token_start != std::string::npos )
    {
      const size_t number_start = token_start + 7;
      const size_t token_end = plain.find(']', number_start);
      if ( token_end == std::string::npos )
        break;

      if ( token_start >= 2 && plain.compare(token_start - 2, 2, "->") == 0 )
      {
        size_t object_start = token_start - 2;
        while ( object_start > 0 && is_identifier_char(plain[object_start - 1]) )
          --object_start;
        if ( object_start == token_start - 2
          || !is_identifier_start(plain[object_start]) )
        {
          token_start = plain.find("VTABLE[", token_end + 1);
          continue;
        }

        const std::string number =
          plain.substr(number_start, token_end - number_start);
        char *number_end = nullptr;
        const uval_t slot = uval_t(::strtoull(number.c_str(), &number_end, 0));
        if ( number_end == number.c_str() || *number_end != '\0' )
        {
          token_start = plain.find("VTABLE[", token_end + 1);
          continue;
        }

        vtable_marker_t candidate;
        candidate.line = vu->cpos.lnnum;
        candidate.start_column = int(token_start);
        candidate.end_column = int(token_end + 1);
        candidate.slot = slot;
        candidate.byte_offset = slot * (inf_is_64bit() ? 8 : 4);
        candidate.object_name =
          plain.substr(object_start, token_start - 2 - object_start).c_str();
        sole_marker = candidate;
        ++valid_token_count;

        if ( vu->cpos.x >= int(token_start) && vu->cpos.x <= int(token_end) )
        {
          *marker = candidate;
          debug_log(
            "rendered fallback exact: line=%d x=%d object=%s slot=0x%" FMT_64 "X text=%s",
            vu->cpos.lnnum,
            vu->cpos.x,
            marker->object_name.c_str(),
            uint64(marker->slot),
            plain.c_str());
          return true;
        }
      }
      token_start = plain.find("VTABLE[", token_end + 1);
    }

    if ( allow_sole_token && valid_token_count == 1 )
    {
      *marker = sole_marker;
      debug_log(
        "rendered fallback sole-token: line=%d x=%d range=%d..%d object=%s slot=0x%" FMT_64 "X text=%s",
        vu->cpos.lnnum,
        vu->cpos.x,
        marker->start_column,
        marker->end_column,
        marker->object_name.c_str(),
        uint64(marker->slot),
        plain.c_str());
      return true;
    }
    return false;
  }

  const vtable_marker_t *find_vtable_marker(
        vdui_t *vu,
        input_device_t input_device,
        vtable_marker_t *fallback)
  {
    if ( vu == nullptr
      || vu->cfunc == nullptr
      || !vu->refresh_cpos(input_device) )
    {
      debug_log("marker lookup failed: no vdui/cfunc/cursor");
      return nullptr;
    }

    const auto found = vtable_markers.find(vu->cfunc->entry_ea);
    if ( found != vtable_markers.end() )
    {
      for ( const vtable_marker_t &marker : found->second )
      {
        debug_log(
          "marker candidate: cursor=(%d,%d) marker=(%d,%d..%d) object=%s slot=0x%" FMT_64 "X",
          vu->cpos.lnnum,
          vu->cpos.x,
          marker.line,
          marker.start_column,
          marker.end_column,
          marker.object_name.c_str(),
          uint64(marker.slot));
        if ( marker.line == vu->cpos.lnnum
          && vu->cpos.x >= marker.start_column
          && vu->cpos.x < marker.end_column )
        {
          return &marker;
        }
      }
    }

    debug_log(
      "stored marker miss: function=%a cursor=(%d,%d), trying rendered fallback",
      vu->cfunc->entry_ea,
      vu->cpos.lnnum,
      vu->cpos.x);
    return parse_rendered_vtable_marker(
      vu,
      fallback,
      input_device == USE_KEYBOARD) ? fallback : nullptr;
  }

  bool show_vtable_index(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker =
      find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
    {
      warning("Place the cursor on a resolved virtual method and press I");
      return false;
    }

    info(
      "%s uses VTABLE[0x%" FMT_64 "X] (byte offset 0x%" FMT_64 "X)",
      marker->display_name.empty() ? "Virtual call" : marker->display_name.c_str(),
      uint64(marker->slot),
      uint64(marker->byte_offset));
    return true;
  }

  bool rename_vtable_target(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker =
      find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    qstring selected_class;
    qstring selected_vtable;
    ea_t selected_vtable_ea = BADADDR;
    if ( !find_object_vtable(
          vu->cfunc,
          marker->object_name,
          &selected_class,
          &selected_vtable,
          &selected_vtable_ea) )
    {
      warning("Could not resolve the VTABLE for '%s'", marker->object_name.c_str());
      return true;
    }

    ea_t selected_target = marker->target;
    if ( selected_target == BADADDR
      && !get_vtable_entry_target(vu->cfunc, *marker, &selected_target) )
    {
      warning(
        "%s[0x%" FMT_64 "X] does not contain a mapped function address",
        selected_vtable.c_str(),
        uint64(marker->slot));
      return true;
    }

    qstring new_name = get_short_name(selected_target);
    std::string display(new_name.c_str());
    const size_t namespace_separator = display.rfind("::");
    if ( namespace_separator != std::string::npos )
      display.erase(0, namespace_separator + 2);
    const std::string selected_prefix =
      std::string(identifier_from_type_name(selected_class).c_str()) + "_";
    if ( display.rfind(selected_prefix, 0) == 0 )
      display.erase(0, selected_prefix.length());
    new_name = display.c_str();
    if ( !ask_str(
          &new_name,
          HIST_IDENT,
          "Rename VTABLE[0x%" FMT_64 "X]. Prefix with AncestorClass:: to set its declaration boundary.",
          uint64(marker->slot)) )
    {
      return true;
    }

    qstring declaring_class = selected_class;
    qstring method_name = new_name;
    qvector<qstring> ancestors;
    collect_ancestor_hierarchy(selected_class, &ancestors);
    size_t matched_prefix_length = 0;
    for ( const qstring &ancestor : ancestors )
    {
      qstring prefix = ancestor;
      prefix.append("::");
      if ( new_name.length() > prefix.length()
        && strncmp(new_name.c_str(), prefix.c_str(), prefix.length()) == 0
        && prefix.length() > matched_prefix_length )
      {
        declaring_class = ancestor;
        method_name = new_name.substr(prefix.length());
        matched_prefix_length = prefix.length();
      }
    }
    if ( matched_prefix_length == 0 && strstr(new_name.c_str(), "::") != nullptr )
    {
      warning(
        "The rename prefix must be the current class or one of its ancestors");
      return true;
    }
    if ( !set_declaring_class_metadata(
          selected_class,
          declaring_class,
          marker->slot) )
    {
      warning(
        "Could not set %s as the declaration boundary for VTABLE[0x%" FMT_64 "X]",
        declaring_class.c_str(),
        uint64(marker->slot));
      return true;
    }

    hierarchy_targets_t targets;
    size_t vtable_count = 0;
    collect_hierarchy_targets(
      selected_class,
      marker->slot,
      &targets,
      &vtable_count);
    if ( targets.empty() )
    {
      warning(
        "No mapped functions found at or below %s for VTABLE[0x%" FMT_64 "X]",
        declaring_class.c_str(),
        uint64(marker->slot));
      return true;
    }
    new_name = method_name;

    size_t renamed_count = 0;
    for ( const hierarchy_target_t &entry : targets )
    {
      if ( new_name.empty() )
      {
        if ( del_global_name(entry.target) )
        {
          ++renamed_count;
          debug_log(
            "N hierarchy unname: class=%s vtable=%s slot=0x%" FMT_64 "X target=%a",
            entry.class_name.c_str(),
            entry.vtable_name.c_str(),
            uint64(marker->slot),
            entry.target);
        }
        continue;
      }
      qstring applied_name;
      if ( targets.size() == 1 )
      {
        applied_name = new_name;
      }
      else
      {
        applied_name = identifier_from_type_name(entry.class_name);
        applied_name.append('_');
        applied_name.append(new_name);
      }
      if ( force_name(entry.target, applied_name.c_str(), SN_NON_AUTO) )
      {
        ++renamed_count;
        debug_log(
          "N hierarchy rename: class=%s vtable=%s slot=0x%" FMT_64 "X target=%a name=%s",
          entry.class_name.c_str(),
          entry.vtable_name.c_str(),
          uint64(marker->slot),
          entry.target,
          applied_name.c_str());
      }
    }
    if ( renamed_count == 0 )
    {
      warning(
        new_name.empty()
          ? "Could not remove any function names in the %s hierarchy"
          : "Could not rename any functions in the %s hierarchy",
        selected_class.c_str());
      return true;
    }
    if ( new_name.empty() )
      msg(
        "Pseudocode Xrefs: removed %" FMT_Z " implementation names at slot 0x%" FMT_64 "\n",
        renamed_count,
        uint64(marker->slot));
    else
      msg(
        "Pseudocode Xrefs: renamed %" FMT_Z " implementations at slot 0x%" FMT_64
        " across %" FMT_Z " named VTABLEs\n",
        renamed_count,
        uint64(marker->slot),
        vtable_count);
    vu->cfunc->refresh_func_ctext();
    return true;
  }

  bool show_hierarchy_versions(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker = find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    qstring selected_class, vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_object_vtable(
          vu->cfunc,
          marker->object_name,
          &selected_class,
          &vtable_name,
          &vtable_ea) )
      return false;

    hierarchy_targets_t entries;
    collect_all_hierarchy_targets(selected_class, marker->slot, &entries);
    if ( entries.empty() )
    {
      warning("No implementations found for VTABLE[0x%" FMT_64 "X]", uint64(marker->slot));
      return true;
    }

    qstring title;
    title.sprnt(
      "%s hierarchy: VTABLE[0x%" FMT_64 "X] implementations",
      selected_class.c_str(),
      uint64(marker->slot));
    hierarchy_popup_t popup(entries, title.c_str());
    const ssize_t selected = popup.choose();
    if ( selected < 0 || selected >= entries.size() )
      return true;

    const hierarchy_target_t &entry = entries[selected];
    switch ( popup.activated_column )
    {
      case 0:
      {
        const int32 ordinal = get_type_ordinal(nullptr, entry.class_name.c_str());
        if ( ordinal > 0 )
          open_loctypes_window(ordinal);
        else
          warning("Local type '%s' was not found", entry.class_name.c_str());
        break;
      }
      case 1:
      {
        const size_t pointer_size = inf_is_64bit() ? 8 : 4;
        jump_to_disassembly(entry.vtable_ea + marker->slot * pointer_size);
        break;
      }
      case 2:
        open_pseudocode(entry.target, 0);
        break;
      case 3:
        jump_to_disassembly(entry.target);
        break;
    }
    return true;
  }

  bool set_declaring_class(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker = find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    qstring selected_class, vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_object_vtable(
          vu->cfunc,
          marker->object_name,
          &selected_class,
          &vtable_name,
          &vtable_ea) )
    {
      return false;
    }

    qvector<qstring> ancestors;
    collect_ancestor_hierarchy(selected_class, &ancestors);
    qstring title;
    title.sprnt(
      "Set declaring class for VTABLE[0x%" FMT_64 "X]",
      uint64(marker->slot));
    declaring_class_popup_t popup(ancestors, title.c_str());
    const ssize_t selected = popup.choose();
    if ( selected < 0 || selected >= ancestors.size() )
      return true;

    const qstring &declaring_class = ancestors[selected];
    if ( !set_declaring_class_metadata(
          selected_class,
          declaring_class,
          marker->slot) )
    {
      warning(
        "Could not store declaring class '%s' for VTABLE[0x%" FMT_64 "X]",
        declaring_class.c_str(),
        uint64(marker->slot));
      return true;
    }

    msg(
      "Pseudocode Xrefs: VTABLE[0x%" FMT_64 "X] is first declared by %s\n",
      uint64(marker->slot),
      declaring_class.c_str());
    return true;
  }

  bool jump_to_vtable_target(
        vdui_t *vu,
        input_device_t input_device,
        bool warn_if_missing)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker =
      find_vtable_marker(vu, input_device, &fallback);
    if ( marker == nullptr )
    {
      debug_log(
        "VTABLE navigation ignored: no marker under %s cursor",
        input_device == USE_MOUSE ? "mouse" : "keyboard");
      if ( warn_if_missing )
        warning("Place the cursor on a VTABLE[...] token and press J");
      return false;
    }
    debug_log(
      "J navigation start: object=%s slot=0x%" FMT_64 "X offset=0x%" FMT_64 "X",
      marker->object_name.c_str(),
      uint64(marker->slot),
      uint64(marker->byte_offset));

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
      debug_log("J navigation failed: lvar '%s' not found", marker->object_name.c_str());
      warning("Could not find the variable '%s'", marker->object_name.c_str());
      return true;
    }

    tinfo_t object_type = object_lvar->type();
    debug_log(
      "J object type: variable=%s type=%s",
      marker->object_name.c_str(),
      object_type.dstr());
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
    debug_log(
      "J vtable resolved: class=%s symbol=%s ea=%a",
      class_name.c_str(),
      vtable_name.c_str(),
      vtable_ea);
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
    debug_log(
      "J slot resolved: entry=%a target=%a mapped=%d",
      entry_ea,
      target,
      is_mapped(target));
    if ( target == BADADDR || !is_mapped(target) )
    {
      warning(
        "VTABLE slot 0x%" FMT_64 "X does not contain a mapped function address",
        uint64(marker->slot));
      return true;
    }

    jumpto(target);
    debug_log("J navigation success: target=%a", target);
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
    if ( shift_state != 0 )
      return 0;

    debug_log(
      "double click: vu=%p function=%a",
      vu,
      vu != nullptr && vu->cfunc != nullptr ? vu->cfunc->entry_ea : BADADDR);
    return plugin->jump_to_vtable_target(vu, USE_MOUSE, false) ? 1 : 0;
  }

  if ( event == hxe_populating_popup )
  {
    TWidget *widget = va_arg(va, TWidget *);
    TPopupMenu *popup = va_arg(va, TPopupMenu *);
    vdui_t *vu = va_arg(va, vdui_t *);
    vtable_marker_t fallback;
    if ( plugin->find_vtable_marker(vu, USE_KEYBOARD, &fallback) != nullptr )
      attach_action_to_popup(
        widget,
        popup,
        VTABLE_DECLARING_ACTION_NAME,
        "Pseudocode Xrefs/");
    return 0;
  }

  if ( event != hxe_keyboard )
    return 0;

  vdui_t *vu = va_arg(va, vdui_t *);
  const int key_code = va_arg(va, int);
  const int shift_state = va_arg(va, int);
  if ( shift_state != 0 )
    return 0;

  if ( key_code == 'N' || key_code == 'n' )
    return plugin->rename_vtable_target(vu) ? 1 : 0;
  if ( key_code == 'K' || key_code == 'k' )
  {
    show_xrefs(vu);
    return 1;
  }
  if ( key_code == 'J' || key_code == 'j' )
  {
    debug_log(
      "keyboard J: vu=%p shift=%d function=%a",
      vu,
      shift_state,
      vu != nullptr && vu->cfunc != nullptr ? vu->cfunc->entry_ea : BADADDR);
    plugin->jump_to_vtable_target(vu, USE_KEYBOARD, true);
    return 1;
  }
  if ( key_code == 'I' || key_code == 'i' )
  {
    plugin->show_vtable_index(vu);
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
