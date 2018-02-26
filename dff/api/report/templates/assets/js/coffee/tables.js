(function() {
  var ChatFragment, DetailTableFragment, NodeGalleryFragment, NodeListFragment, NodeTableFragment, TableFragment,
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __hasProp = Object.prototype.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor; child.__super__ = parent.prototype; return child; };

  namespace("fragments", {
    NodeListFragment: NodeListFragment = (function(_super) {

      __extends(NodeListFragment, _super);

      function NodeListFragment(json, id) {
        this.json = json;
        this.id = id;
        this.render = __bind(this.render, this);
        NodeListFragment.__super__.constructor.call(this, this.json, this.id);
        this.view = null;
        this.container = $('<div>').addClass('container');
        this.createView(this.json.view);
      }

      NodeListFragment.prototype.setTitle = function() {};

      NodeListFragment.prototype.createView = function(viewid) {
        var id, v;
        if (this.view) this.view.clear();
        this.createHeader();
        id = Math.floor((Math.random() * 1000) + 1);
        if (viewid === 0) {
          v = new fragments.NodeTableFragment(this.json, id);
        } else {
          v = new fragments.NodeGalleryFragment(this.json, id);
        }
        if (this.view) {
          delete this.view;
          this.view = v;
          return this.view.render(this.container);
        } else {
          return this.view = v;
        }
      };

      NodeListFragment.prototype.render = function(rootDom) {
        NodeListFragment.__super__.render.apply(this, arguments);
        this.html.append(this.container);
        return this.view.render(this.container);
      };

      NodeListFragment.prototype.createHeader = function() {
        var btngroup, btntoolbar, galleryview, gid, header, tableview, tid,
          _this = this;
        gid = Math.floor((Math.random() * 1000) + 1);
        tid = Math.floor((Math.random() * 1000) + 1);
        header = $('<div>').addClass('container');
        btntoolbar = $('<div>').addClass('btn-toolbar');
        btngroup = $('<div>').addClass('btn-group');
        galleryview = $('<button>').addClass('btn').append($('<i>').addClass('icon-picture')).attr('id', gid.toString());
        tableview = $('<button>').addClass('btn').append($('<i>').addClass('icon-th-list')).attr('id', tid.toString());
        btngroup.append(galleryview);
        btngroup.append(tableview);
        btntoolbar.append(btngroup);
        header.append(btntoolbar);
        this.container.append(header);
        $('button#' + gid.toString()).live('click', function(event) {
          event.preventDefault();
          event.stopImmediatePropagation();
          return _this.createView(1);
        });
        return $('button#' + tid.toString()).live('click', function(event) {
          event.preventDefault();
          event.stopImmediatePropagation();
          return _this.createView(0);
        });
      };

      return NodeListFragment;

    })(fragments.FObject),
    NodeTableFragment: NodeTableFragment = (function(_super) {

      __extends(NodeTableFragment, _super);

      function NodeTableFragment(json, id) {
        this.json = json;
        this.id = id;
        this.connect = __bind(this.connect, this);
        this.setup = __bind(this.setup, this);
        this.render = __bind(this.render, this);
        NodeTableFragment.__super__.constructor.call(this, this.json, this.id);
        this.fmanager = new fragments.Manager();
        this.container = $('<div>').addClass('container');
        this.table = null;
        this.createTable();
        this.setup();
        this.connect();
      }

      NodeTableFragment.prototype.render = function(rootDom) {
        var dth,
          _this = this;
        NodeTableFragment.__super__.render.apply(this, arguments);
        this.html.append(this.container);
        dth = $('<th>').attr('width', '1%');
        $('table.table#node_table_' + this.id + ' thead tr').each(function(id, tr) {
          return $(tr).append(dth);
        });

        return $('table.table#node_table_' + this.id).dataTable(this.settings);
      };

      NodeTableFragment.prototype.createTable = function() {
        var head, htr, root, row, t, table, th, _i, _len, _ref;
        root = $('<div>').addClass("dataTables_wrapper form-inline").attr('role', 'grid');
        row = $('<div>').addClass("row-fluid");
        table = $('<table>').addClass("table table-striped table-bordered dataTable").attr('id', 'node_table_' + this.id).attr("width", "100%");
        head = $('<thead>');
        htr = $('<tr>').attr('role', 'row');
        _ref = this.json.thead;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          th = _ref[_i];
          t = $('<th>').addClass('sorting').attr('role', 'columnheader').attr('tabindex', '0').attr('aria-controls', 'node_table_' + this.id).append(th);
          htr.append(t);
        }
        head.append(htr);
        table.append(head);
        row.append(table);
        root.append(row);
        return this.container.append(root);
      };

      $.fn.dataTableExt.oApi.fnHideEmptyColumns = function ( oSettings, tableObject )
      {
        var selector = tableObject.selector;
        var columnsToHide = [];
 
        $(selector).find('th').each(function(i) {
 
        var columnIndex = $(this).index();
        var rows = $(this).parents('table').find('tr td:nth-child(' + (i + 1) + ')'); //Find all rows of each column 
        var rowsLength = $(rows).length;
        var emptyRows = 0;
 
        rows.each(function(r) {
            if (this.innerHTML == '')
                emptyRows++;
        }); 
 
        if(emptyRows == rowsLength) {
            columnsToHide.push(columnIndex);  //If all rows in the colmun are empty, add index to array
         } 

        });
        for(var i=0; i< columnsToHide.length; i++) {
          tableObject.fnSetColumnVis( columnsToHide[i], false ); //Hide columns by index
        }
        tableObject.fnAdjustColumnSizing();
      }

      NodeTableFragment.prototype.setup = function() {
        var add, head, id, t, th, value, _i, _len, _ref, _results;
        this.oldStart = 0;
        this.settings = {
          "bProcessing" : true,
          "bDeferRender" : true,
          "responsive" : true,
          "aaData": this.json.data,
          "sDom": "<'row-fluid'<'span6'l><'span6'f>r>t<'row-fluid'<'span6'i><'span6'p>>",
          "sPaginationType": "bootstrap",
          "fnDrawCallback" : function(oSettings)
           {
             if (oSettings._iDisplayStart != this.oldStart) 
              {
                $('html,body').animate({scrollTop: 0 }, 500);
                this.oldStart = oSettings._iDisplayStart;
              }
              $("img.lazy").lazyload(); 
           },
          "fnRowCallback": function(nRow, aData, iDisplayIndex, iDisplayIndexFull) {
            var dtd;

            if (!$(nRow).find('td.detail_img')[0]) {
              dtd = $('<td>').append('<img src="assets/img/details_open.png">');
              dtd.addClass('center');
              dtd.addClass('detail_img');
              $(nRow).addClass('main');
              return $(nRow).append(dtd);
            }
          },
          "fnInitComplete": function()
          {
            try {
            this.fnHideEmptyColumns(this);
            }
            catch (err) {
           }
          },
        };
        head = [];
        _ref = this.json.thead;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          th = _ref[_i];
          t = {
            "mData": th
          };
          head.push(t);
        }
        add = {
          "aoColumns": head,
          "aoColumnDefs": [
            {
              "aTargets": [0],
              "mRender": function(data, type, full) {
                if (full.file) {
                  if (full.thumb) {
                    return '<span><img class="lazy" data-original="' + full.thumb+ '" ><a href="' + full.file + '"> ' + data + '</a></span>';
                        
                  } else {
                    return '<a href="' + full.file + '"> ' + data + '</a>';
                  }
                }
                return data;
              }
            }
          ]
        };
        _results = [];
        for (id in add) {
          value = add[id];
          _results.push(this.settings[id] = value);
        }
        return _results;
      };

      NodeTableFragment.prototype.connect = function() {
        var _this = this;

        $('#node_table_' + this.id + ' tbody tr.main').live('mouseover', function(event) {
          return $(event.currentTarget).addClass('info');
        });
        $('#node_table_' + this.id + ' tbody tr.main').live('mouseout', function(event) {
          return $(event.currentTarget).removeClass('info');
        });
        return $('#node_table_' + this.id + ' tbody td.detail_img').live('click', function(event) {

          var colspan, data, dtd, dtr, fid, fragment, table, tr;
          event.preventDefault();
          event.stopImmediatePropagation();
          tr = $(event.currentTarget).parent();
          table = $('table#node_table_' + _this.id).dataTable();
          data = table.fnGetData(tr[0]);        
          if (data) {
            if (tr.hasClass('open')) {
              fragment = tr.next().find($('.fragment'));
              fid = fragment.attr('id');
              tr.next().remove();
              _this.fmanager.fragments.splice(fid, 1);
              return tr.removeClass('open success');
            } else {
              tr.addClass('success');
              fragment = _this.fmanager.create(data);
              colspan = table.fnSettings()['aoColumns'].length;
              colspan = colspan + 1;
              tr.addClass('open');
              dtr = $('<tr>');
              dtd = $('<td>').attr('colspan', colspan.toString());
              dtr.append(dtd);
              tr.after(dtr);
              fragment.render(dtd);
            }
          }
        });
      };

      return NodeTableFragment;

    })(fragments.FObject),
    NodeGalleryFragment: NodeGalleryFragment = (function(_super) {

      __extends(NodeGalleryFragment, _super);

      function NodeGalleryFragment(json, id) {
        this.json = json;
        this.id = id;
        this.render = __bind(this.render, this);
        NodeGalleryFragment.__super__.constructor.call(this, this.json, this.id);
        this.container = $('<div>').addClass('container');
        this.setItemSelection();
        this.max_visible_pages = 10;
        this.visible_items = 99;
        this.current_page = 0;
        this.refresh();
        $('select#' + this.id + '.itemselection').trigger("change", 200);
        $('select#' + this.id + '.itemselection').trigger("change", 100);
      }

      NodeGalleryFragment.prototype.configurePagination = function() {
        this.pages = parseInt(this.json.data.length / this.visible_items);
        if (this.json.data.length % this.visible_items > 0) {
          this.pages = this.pages + 1;
        }
        this.pages = this.pages - 1;
        if (this.pages < 0) return this.pages = 0;
      };

      NodeGalleryFragment.prototype.setItemSelection = function() {
        var _this = this;
        this.selection = $('<select>').append($('<option>').append(100)).append($('<option>').append(200)).append($('<option>').append(500));
        this.selection.addClass('itemselection');
        this.selection.attr('id', this.id);
        this.html.append(this.selection);
        return $('select#' + this.id + '.itemselection').live('change', function(event) {
          _this.visible_items = event.currentTarget.value - 1;
          return _this.refresh();
        });
      };

      NodeGalleryFragment.prototype.pagination = function() {
        var div_pages, end, link, num, paginate, start, stop, ul,
          _this = this;
        $('div.row-fluid#pagination').remove();
        paginate = $('<div>').addClass("row-fluid").attr("id", "pagination");
        div_pages = $('<div>').addClass("pagination pagination-centered");
        ul = $('<ul>').attr("id", "pagination");
        start = this.current_page - (this.current_page % this.max_visible_pages);
        end = start + this.max_visible_pages;
        stop = end > this.pages ? this.pages : end;
        this.previous(ul);
        for (num = start; start <= stop ? num <= stop : num >= stop; start <= stop ? num++ : num--) {
          link = $('<a>').attr('href', '#').append(num + 1);
          link.bind('click', function(event) {
            _this.current_page = parseInt($(event.target).text()) - 1;
            return _this.refresh();
          });
          if (num === this.current_page) {
            ul.append($('<li>').addClass('active').append(link));
          } else {
            ul.append($('<li>').append(link));
          }
        }
        this.next(ul);
        div_pages.append(ul);
        paginate.append(div_pages);
        return this.container.append(paginate);
      };

      NodeGalleryFragment.prototype.next = function(ul) {
        var a, li,
          _this = this;
        li = $('<li>');
        a = $('<a>').attr("href", "#").append(">>");
        if (this.current_page === this.pages) {
          li.addClass('disabled');
        } else {
          a.bind('click', function(event) {
            _this.current_page = _this.current_page + 1;
            return _this.refresh();
          });
        }
        return ul.append(li.append(a));
      };

      NodeGalleryFragment.prototype.previous = function(ul) {
        var a, li,
          _this = this;
        li = $('<li>');
        a = $('<a>').attr("href", "#").append("<<");
        if (this.current_page === 0) {
          li.addClass('disabled');
        } else {
          a.bind('click', function(event) {
            _this.current_page = _this.current_page - 1;
            return _this.refresh();
          });
        }
        return ul.append(li.append(a));
      };

      NodeGalleryFragment.prototype.createGallery = function() {
        var data, end, i, img, link, root, sdata, start, stop, _len;
        $('div#myGallery').remove();
        data = this.json.data; 
        start = this.current_page * this.visible_items;
        start = this.current_page > 0 ? start + 1 : start;
        end = start + this.visible_items;
        stop = end > data.length ? data.length : end;
        root = $('<div>').attr('id', 'myGallery');
        var extArray = ["jpg", "jpeg", "png", "gif"];

        sdata = data.slice(start, stop + 1 || 9e9);
        for (i = 0, _len = sdata.length; i < _len; i++) 
        {
          currentIndex = i + start;
          img = data[currentIndex];
          if (img.thumb)
          {
            var ext = img.file.substr(img.file.lastIndexOf('.') + 1);
            var haveCompatibleExt= (extArray.indexOf(ext.toLowerCase()) > -1);

            if (haveCompatibleExt) 
              link = $('<a>').attr('href', img.file).addClass('img').attr('id', currentIndex).attr('title', img.name).append($('<img>').attr('src', img.thumb).attr('alt', img.name));
            else
              link = $('<a>').attr('href', img.thumb).addClass('img').attr('id', currentIndex).attr('title', img.name).append($('<img>').attr('src', img.thumb).attr('alt', img.name));
            root.append(link);
          }
        }
        return this.container.append(root);
      };

      NodeGalleryFragment.prototype.refresh = function() {
        var _this = this;
        this.configurePagination();
        this.createGallery().find('#myGallery').justifiedGallery({
          lastRow: 'nojustify',
          rowHeight : 128,
          rel : 'gallery1',
          maxRowHeight : 128,
          margins: 3
        }).on('jg.complete', function() {
          return $(this).find('a').colorbox({
                transition:"none", width:"97%", height:"97%",
                maxWidth : '97%',
                maxHeight : '97%',
                opacity : 0.8,
                transition : 'elastic',
                onComplete : function()
                {
                  var id = this.getAttribute("id");
                  data = _this.json.data[id]; 

                  var linkToFile =  data.file;
                  $('#cboxMiddleRight').empty();
                  $('#cboxMiddleRight').append('<a href="' + linkToFile + '">Original</a>');

                  var details = _this.json.data[id].row_details.data;
                  for (moduleName in details)
                  {   
                    $('#cboxMiddleRight').append('<tr><td>' + moduleName + ' :</td></tr>');
                    module = details[moduleName];
                    for (attribute in module)
                    {
                      value = module[attribute];
                      if (value != '')
                        $('#cboxMiddleRight').append('<tr><td>' + attribute + ': </td><td>' + value + '</td></tr>');
                    }
                  }
                } 
                });
          });

        return this.pagination();
      };

      NodeGalleryFragment.prototype.render = function(rootDom) {
        NodeGalleryFragment.__super__.render.apply(this, arguments);
        return this.html.append(this.container);
      };

      return NodeGalleryFragment;

    })(fragments.FObject),
    DetailTableFragment: DetailTableFragment = (function(_super) {

      __extends(DetailTableFragment, _super);

      function DetailTableFragment(json, id) {
        this.json = json;
        this.id = id;
        this.connect = __bind(this.connect, this);
        this.setup = __bind(this.setup, this);
        this.render = __bind(this.render, this);
        DetailTableFragment.__super__.constructor.call(this, this.json, this.id);
        this.fmanager = new fragments.Manager();
        this.table = null;
        this.createTable();
        this.setup();
        this.connect();
      }

      DetailTableFragment.prototype.render = function(rootDom) {
        var dth,
          _this = this;
        DetailTableFragment.__super__.render.apply(this, arguments);
        dth = $('<th>');
        $('table.table#dtable_' + this.id + ' thead tr').each(function(id, tr) {
          return $(tr).prepend(dth);
        });
        return $('table.table#dtable_' + this.id).dataTable(this.settings);
      };

      DetailTableFragment.prototype.createTable = function() {
        var head, htr, root, row, t, table, th, _i, _len, _ref;
        root = $('<div>').addClass("container").addClass("dataTables_wrapper form-inline").attr('role', 'grid');
        row = $('<div>').addClass("row-fluid");
        table = $('<table>').addClass("table table-striped table-bordered dataTable").attr('id', 'dtable_' + this.id).attr("width", "100%");
        head = $('<thead>');
        htr = $('<tr>').attr('role', 'row');
        _ref = this.json.thead;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          th = _ref[_i];
          t = $('<th>').addClass('sorting').attr('width', '50%').attr('role', 'columnheader').attr('tabindex', '0').attr('aria-controls', 'dtable_' + this.id).append(th);
          htr.append(t);
        }
        head.append(htr);
        table.append(head);
        root.append(table);
        root.append(row);
        return this.html.append(root);
      };

      DetailTableFragment.prototype.setup = function() {
        var add, head, id, t, th, value, _i, _len, _ref, _results;
        this.settings = {
          "aaData": this.json.data,
          "sDom": "<'row-fluid'<'span6'l><'span6'f>r>t<'row-fluid'<'span6'i><'span6'p>>",
          "sPaginationType": "bootstrap",
          "fnRowCallback": function(nRow, aData, iDisplayIndex, iDisplayIndexFull) {
            var dtd;
            if (!$(nRow).find('td.detail_img')[0]) {
              dtd = $('<td>').append('<img src="assets/img/details_open.png">');
              dtd.addClass('center');
              dtd.addClass('detail_img');
              $(nRow).addClass('main');
              return $(nRow).prepend(dtd);
            }
          }
        };
        head = [];
        _ref = this.json.thead;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          th = _ref[_i];
          t = {
            "mData": th
          };
          head.push(t);
        }
        add = {
          "aoColumns": head,
          "aoColumnDefs": [
            {
              "bSortable": true,
              "aTargets": [0],
              "mRender": function(data, type, full) {
                if (full.thumb) {
                  return '<span><img src="' + full.thumb + '" class="thumb"> ' + data + '</span>';
                }
                return data;
              }
            }
          ]
        };
        _results = [];
        for (id in add) {
          value = add[id];
          _results.push(this.settings[id] = value);
        }
        return _results;
      };

      DetailTableFragment.prototype.connect = function() {
        var _this = this;
        $('#dtable_' + this.id + ' tbody tr.main').live('mouseover', function(event) {
          return $(event.currentTarget).addClass('info');
        });
        $('#dtable_' + this.id + ' tbody tr.main').live('mouseout', function(event) {
          return $(event.currentTarget).removeClass('info');
        });
        return $('#dtable_' + this.id + ' tbody tr.main').live('click', function(event) {
          var colspan, data, dtd, dtr, fid, fragment, table, tr;
          event.preventDefault();
          event.stopImmediatePropagation();
          tr = event.currentTarget;
          table = $('table#dtable_' + _this.id).dataTable();
          data = table.fnGetData(tr);
          if (data['row_details']) {
            if ($(tr).hasClass('open')) {
              fragment = $(tr).next().find($('.fragment'));
              fid = fragment.attr('id');
              $(tr).next().remove();
              _this.fmanager.fragments.splice(fid, 1);
              $(tr).removeClass('open success');
              dtd = $(tr).find($('.detail_img'));
              dtd.empty();
              return dtd.append('<img src="assets/img/details_open.png">');
            } else {
              $(tr).addClass('success');
              $(tr).addClass('open');
              dtd = $(tr).find($('.detail_img'));
              dtd.empty();
              dtd.append('<img src="assets/img/details_close.png">');
              fragment = _this.fmanager.create(data['row_details']);
              colspan = table.fnSettings()['aoColumns'].length;
              colspan = colspan + 1;
              dtr = $('<tr>');
              dtd = $('<td>').attr('colspan', colspan.toString());
              dtr.append(dtd);
              $(tr).after(dtr);
              return fragment.render(dtd);
            }
          }
        });
      };

      return DetailTableFragment;

    })(fragments.FObject),
    TableFragment: TableFragment = (function(_super) {

      __extends(TableFragment, _super);

      function TableFragment(json, id) {
        this.json = json;
        this.id = id;
        this.setup = __bind(this.setup, this);
        this.render = __bind(this.render, this);
        TableFragment.__super__.constructor.call(this, this.json, this.id);
        this.html = $('<div>');
        this.table = null;
        this.createTable();
        this.setup();
      }

      TableFragment.prototype.render = function(rootDom) {
        TableFragment.__super__.render.apply(this, arguments);
        return $('table.table#table_' + this.id).DataTable(this.settings);
      };

      TableFragment.prototype.createTable = function() {
        var head, htr, root, row, t, table, th, _i, _len, _ref;
        root = $('<div>').addClass("dataTables_wrapper form-inline").attr('role', 'grid');
        row = $('<div>').addClass("row-fluid");
        table = $('<table>').addClass("table table-striped table-bordered dataTable").attr('id', 'table_' + this.id).attr('width', '100%');
        head = $('<thead>');
        htr = $('<tr>').attr('role', 'row');
        _ref = this.json.thead;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          th = _ref[_i];
          t = $('<th>').addClass('sorting').attr('role', 'columnheader').attr('tabindex', '0').attr('aria-controls', 'table_' + this.id).append(th);
          htr.append(t);
        }
        head.append(htr);
        table.append(head);
        row.append(table);
        root.append(row);
        return this.html.append(root);
      };

      TableFragment.prototype.setup = function() {
        return this.settings = {
          "aaData": this.json.data,
          "aoColumns": this.json.thead,
          "bPaginate": false,
          'bFilter': false,
          "sDom": 't'
        };
      };

      return TableFragment;

    })(fragments.FObject),
    ChatFragment: ChatFragment = (function(_super) {

      __extends(ChatFragment, _super);

      function ChatFragment(json, id) {
        this.json = json;
        this.id = id;
        this.render = __bind(this.render, this);
        ChatFragment.__super__.constructor.call(this, this.json, this.id);
        this.createChats();
      }

      ChatFragment.prototype.render = function(rootDom) {
        return ChatFragment.__super__.render.apply(this, arguments);
      };

      ChatFragment.prototype.createChats = function() {
        var chat, chatbody, chattable, date, m, message, tr, user, _i, _j, _len, _len2, _ref, _ref2, _results;
        _ref = this.json.data;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          chat = _ref[_i];
          date = $('<h4>').append(chat.date);
          this.html.append(date);
          chattable = $('<table>').addClass("table").addClass("table-condensed").addClass("table-chat");
          chatbody = $('<tbody>');
          _ref2 = chat.messages;
          for (_j = 0, _len2 = _ref2.length; _j < _len2; _j++) {
            message = _ref2[_j];
            tr = $('<tr>');
            date = $('<td>').addClass('date');
            date.append(message[0]);
            tr.append(date);
            user = $('<td>').addClass('username');
            user.append(message[1]);
            tr.append(user);
            m = $('<td>').addClass('message');
            m.append(message[2]);
            tr.append(m);
            chatbody.append(tr);
          }
          chattable.append(chatbody);
          _results.push(this.html.append(chattable));
        }
        return _results;
      };

      return ChatFragment;

    })(fragments.FObject)
  });

}).call(this);
